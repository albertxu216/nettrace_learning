#include <sys/sysinfo.h>
#include <parse_sym.h>

#include "trace.h"
#include "progs/kprobe.skel.h"
#include "analysis.h"

#define MAX_CPU_COUNT 1024

const char *kprobe_type = "/sys/bus/event_source/devices/kprobe/type";

struct list_head cpus[MAX_CPU_COUNT];
trace_ops_t probe_ops;
static struct kprobe *skel;

static void probe_trace_attach_manual(char *prog_name, char *func,
				      bool retprobe)
{
	struct bpf_program *prog;
	bool legacy;
	int err;

	prog = bpf_pbn(skel->obj, prog_name);
	if (!prog) {
		pr_verb("failed to find prog %s\n", prog_name);
		return;
	}

	bpf_program__set_autoattach(prog, false);
	legacy = !file_exist(kprobe_type);

again:
	if (!legacy)
		err = libbpf_get_error(bpf_program__attach_kprobe(prog,
				       retprobe, func));
	else
		err = compat_bpf_attach_kprobe(bpf_program__fd(prog),
					       func, retprobe);

	if (err && !legacy) {
		pr_verb("retring to attach in legacy mode, prog=%s, func=%s\n",
			prog_name, func);
		legacy = true;
		goto again;
	}

	if (err) {
		pr_err("failed to manually attach program prog=%s, func=%s\n",
		       prog_name, func);
		return;
	}

	pr_verb("manually attach prog %s success\n", prog_name);
}

static int probe_trace_attach()
{
	char kret_name[128];
	trace_t *trace;
	/*1. 手动加载挂载点*/
	trace_for_each(trace) {
		/*需要手动挂载*/
		if (!(trace->status & TRACE_ATTACH_MANUAL))
			continue;
		/*手动挂载kprobe kretprobe*/
		probe_trace_attach_manual(trace->prog, trace->name, false);
		if (!trace_is_ret(trace))
			continue;

		sprintf(kret_name, "ret%s", trace->prog);
		probe_trace_attach_manual(kret_name, trace->name, true);
	}
	/*2. 自动加载挂载点*/
	return kprobe__attach(skel);
}

/* In kprobe, we only enable the monitor for the traces with "any" rule */
static void probe_check_monitor()
{
	trace_t *trace;

	if (trace_ctx.mode != TRACE_MODE_MONITOR)
		return;

	trace_for_each(trace) {
		if (!trace_is_func(trace) || trace_is_invalid(trace))
			continue;

		/* kprobe don't support to monitor function exit */
		if (trace->monitor == TRACE_MONITOR_EXIT) {
			pr_debug("disabled monitor_exit for kprobe\n");
			trace_set_invalid_reason(trace, "monitor");
		}
	}
}

/*加载基于 kprobe 的 eBPF 程序，
包括初始化参数、加载 eBPF 程序、配置性能事件映射表和其他相关设置*/
static int probe_trace_load()
{
	/*1. 定义并初始化 bpf_object_open_opts 结构体*/
	DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts,
		.btf_custom_path = trace_ctx.args.btf_path,
	);
	int i = 0;
	/*2. 使用预定义的 kprobe skeleton 打开 eBPF 程序，并应用初始化的 opts 配置 */
	skel = kprobe__open_opts(&opts);
	if (!skel) {
		pr_err("failed to open kprobe-based eBPF\n");
		goto err;
	}
	pr_debug("eBPF is opened successfully\n");

	/* 3. 设置 perf event map 的最大条目数 
	 *    将 perf event map 的最大条目数设置为当前 CPU 数量
	 */
	bpf_map__set_max_entries(skel->maps.m_event, get_nprocs_conf());

	/* 4. 初始化 BPF 程序的类型 
	 *    配置为 kprobe 类型的 BPF 程序
	 */
	bpf_func_init(skel, BPF_PROG_TYPE_KPROBE);

	/* 5. 将 skeleton 的 BPF 对象指针保存到 trace_ctx 的 obj 字段 */
	trace_ctx.obj = skel->obj;

	/* 6. 执行预加载和加载操作 
	 *    trace_pre_load 检查并禁用无效或未启用的程序，
	 *    kprobe__load 加载 BPF 程序 
	 */
	if (trace_pre_load() || kprobe__load(skel)) {
		pr_err("failed to load kprobe-based eBPF\n");
		goto err;
	}
	pr_debug("eBPF is loaded successfully\n");

	/* 7. 配置运行时参数 
	 *    将用户传递的配置参数写入到 BPF 的全局 BSS 段
	 */
	bpf_set_config(skel, bss, trace_ctx.bpf_args);
	
	/* 8. 初始化每个 CPU 的链表 
	 *    遍历所有可能的 CPU，将每个 CPU 对应的链表初始化为一个空列表
	 */
	for (; i < ARRAY_SIZE(cpus); i++)
		INIT_LIST_HEAD(&cpus[i]);

	return 0;
err:
	return -1;
}

static bool is_trace_supported(trace_t *trace)
{
	struct kprobe *tmp = kprobe__open();
	struct bpf_program *prog;
	int err;

	bpf_object__for_each_program(prog, tmp->obj) {
		if (strcmp(trace->prog, bpf_program__name(prog)) != 0)
			bpf_program__set_autoload(prog, false);
	}
	err = kprobe__load(tmp);
	kprobe__destroy(tmp);

	if (err)
		pr_verb("kernel feature probe failed for trace: %s\n",
			trace->prog);
	else
		pr_debug("kernel feature probe success for trace: %s\n",
			 trace->prog);

	return err == 0;
}

static void probe_trace_feat_probe()
{
	trace_t *trace;

	trace_for_each(trace) {
		if (!trace->probe || !trace_is_usable(trace))
			continue;
		if (!is_trace_supported(trace))
			trace_set_invalid(trace);
	}
}

void probe_trace_close()
{
	if (skel)
		kprobe__destroy(skel);
	skel = NULL;
}

static analyzer_result_t probe_analy_exit(trace_t *trace, analy_exit_t *e)
{
	analy_entry_t *pos;
	int cpu = e->cpu;

	if (cpu > MAX_CPU_COUNT) {
		pr_err("cpu count is too big\n");
		goto out;
	}

	if (list_empty(&cpus[cpu])) {
		pr_debug("no entry found for exit: %s on cpu %d (list empty)\n",
			 trace->name, cpu);
		goto out;
	}

	list_for_each_entry(pos, &cpus[cpu], cpu_list) {
		if (pos->event->func == e->event.func)
			goto found;
	}
	pr_debug("no entry found for exit: %s on cpu %d; func: %d, "
		 "last_func: %d\n", trace->name, cpu, e->event.func,
		 pos->event->func);
	goto out;
found:
	pos->status |= ANALY_ENTRY_RETURNED;
	pos->priv = e->event.val;
	list_del(&pos->cpu_list);
	put_fake_analy_ctx(pos->fake_ctx);
	e->entry = pos;
	pos->status &= ~ANALY_ENTRY_ONCPU;
	pr_debug("found exit for entry: %s(%x) on cpu %d with return "
		 "value %llx, ctx:%llx:%u\n", trace->name, pos->event->key, cpu,
		 e->event.val, PTR2X(pos->ctx), pos->ctx->refs);
out:
	return RESULT_CONT;
}

static analyzer_result_t probe_analy_entry(trace_t *trace, analy_entry_t *e)
{
	struct list_head *list;

	if (!trace_is_ret(trace)) {
		pr_debug("entry found for %s(%llx), ctx:%llx:%d\n", trace->name,
			 (u64)e->event->key, PTR2X(e->ctx),
			 e->ctx->refs);
		goto out;
	}
	list = &cpus[e->cpu];
	list_add(&e->cpu_list, list);
	get_fake_analy_ctx(e->fake_ctx);
	pr_debug("mounted entry %s(%llx) on cpu %d, ctx:%llx:%d\n", trace->name,
		 (u64)e->event->key, e->cpu, PTR2X(e->ctx),
		 e->ctx->refs);
	e->status |= ANALY_ENTRY_ONCPU;

out:
	return RESULT_CONT;
}

static void probe_trace_ready()
{
	bpf_set_config_field(skel, bss, bpf_args_t, ready, true);
}

#ifdef __F_STACK_TRACE
static void probe_print_stack(int key)
{
	if (key <= 0)
	{
		pr_info("Call Stack Error! Invalid stack id:%d.\n", key);
		return;
	}

	int map_fd = bpf_map__fd(skel->maps.m_stack);
	__u64 ip[PERF_MAX_STACK_DEPTH] = {};
	struct sym_result *sym;
	int i = 0;

	if (bpf_map_lookup_elem(map_fd, &key, ip)) {
		pr_info("Call Stack Error!\n");
		return;
	}

	pr_info("Call Stack:\n");
	for (; i < PERF_MAX_STACK_DEPTH && ip[i]; i++) {
		sym = sym_parse(ip[i]);
		if (!sym)
			break;
		pr_info("    -> %s\n", sym->desc);
	}
	pr_info("\n");
}
#else
static void probe_print_stack(int key) { }
#endif

static bool probe_trace_supported()
{
	return true;
}

analyzer_t probe_analyzer = {
	.mode = TRACE_MODE_CTX_MASK | TRACE_MODE_TINY_MASK,
	.analy_entry = probe_analy_entry,
	.analy_exit = probe_analy_exit,
};

trace_ops_t probe_ops = {
	.trace_attach = probe_trace_attach,
	.trace_load = probe_trace_load,
	.trace_close = probe_trace_close,
	.trace_ready = probe_trace_ready,
	.trace_feat_probe = probe_trace_feat_probe,
	.trace_supported = probe_trace_supported,
	.print_stack = probe_print_stack,
	.prepare_traces = probe_check_monitor,
	.analyzer = &probe_analyzer,
};
