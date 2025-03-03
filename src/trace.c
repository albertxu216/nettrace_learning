// SPDX-License-Identifier: MulanPSL-2.0

#include <stdio.h>
#include <list.h>
#include <errno.h>

#include <parse_sym.h>

#include "trace.h"
#include "analysis.h"
#include "dropreason.h"

const char *cond_pre = "verlte() { [ \"$1\" = \"$2\" ] && echo 0 && return; "
		       "[ \"$1\" = \"$(/bin/echo -e \"$1\\n$2\" | sort -V | head -n1)\" ] "
		       "&& echo -1 && return; echo 1; }";

trace_context_t trace_ctx = {
	.mode = TRACE_MODE_TIMELINE,
};

extern trace_ops_t tracing_ops;
extern trace_ops_t probe_ops;
trace_ops_t *trace_ops_all[] = { &tracing_ops, &probe_ops };

static bool trace_group_valid(trace_group_t *group)
{
	trace_list_t *trace_list;
	trace_group_t *pos;

	if (!list_empty(&group->traces)) {
		list_for_each_entry(trace_list, &group->traces, list)
			if (!trace_is_invalid(trace_list->trace))
				return true;
		return false;
	}

	if (!list_empty(&group->children)) {
		list_for_each_entry(pos, &group->children, list)
			if (trace_group_valid(pos))
				return true;
	}
	return false;
}

static void __print_trace_group(trace_group_t *group, int level)
{
	char prefix[32] = {}, buf[32], *name;
	trace_list_t *trace_list;
	trace_group_t *pos;
	trace_t *trace;
	u32 status;
	int i = 0;

	for (; i< level; i++)
		prefix[i] = '\t';

	if (!trace_group_valid(group))
		return;

	pr_info("%s"PFMT_EMPH"%s"PFMT_END": %s\n", prefix, group->name,
		group->desc);
	if (!list_empty(&group->traces))
		goto print_trace;

	if (list_empty(&group->children))
		return;

	list_for_each_entry(pos, &group->children, list)
		__print_trace_group(pos, level + 1);

	return;
print_trace:
	list_for_each_entry(trace_list, &group->traces, list) {
		trace = trace_list->trace;
		status = trace->status;

#if 1
		if (trace_is_invalid(trace))
			continue;
#endif

		buf[0] = '\0';
		if (status & TRACE_LOADED)
			sprintf_end(buf, ",%s", PFMT_EMPH_STR("loaded"));
#if 0
		if (trace_is_enable(trace))
			sprintf_end(buf, ",%s", PFMT_EMPH_STR("enabled"));
#endif
		if (status & TRACE_INVALID)
			sprintf_end(buf, ",%s", PFMT_WARN_STR("invalid"));

		if (trace->monitor)
			sprintf_end(buf, ",%s", PFMT_WARN_STR("monitor"));

		/* skip the prefix of __trace_ */
		name = trace->prog + TRACE_PREFIX_LEN - 1;
		if (buf[0]) {
			buf[0] = ' ';
			pr_info("%s  - %s:%s\n",  prefix, name, buf);
		} else {
			pr_info("%s  - %s\n",  prefix, name);
		}
	}
}

void trace_show(trace_group_t *group)
{
	__print_trace_group(group, 0);
}

static trace_group_t *_search_trace_group(char *name, trace_group_t *group)
{
	trace_group_t *pos, *tmp;

	if (strcmp(group->name, name) == 0)
		return group;

	list_for_each_entry(pos, &group->children, list) {
		tmp = _search_trace_group(name, pos);
		if (tmp)
			return tmp;
	}

	return NULL;
}

trace_group_t *search_trace_group(char *name)
{
	return _search_trace_group(name, &root_group);
}

trace_t *search_trace_enabled(char *name)
{
	trace_t *t;

	trace_for_each(t) {
		if (strcmp(t->name, name) == 0)
			return t;
	}
	return NULL;
}

static int trace_set_target(trace_t *t, int target)
{
	int err = 0;

	switch (target) {
	case 1:
		trace_set_enable(t);
		break;
	case 2:
		err = trace_set_stack(t);
		break;
	case 3:
		trace_set_status(t->index, FUNC_STATUS_MATCHER);
		break;
	case 4:
		trace_set_invalid_reason(t, "exclude");
		break;
	case 5:
		trace_set_status(t->index, FUNC_STATUS_CFREE);
		t->status |= TRACE_CFREE;
		break;
	}

	return err;
}

int trace_enable(char *name, int target)
{
	bool found = false;
	int err = 0;
	trace_t *t;

	trace_for_each(t) {
		if (strcmp(t->name, name))
			continue;

		err = trace_set_target(t, target);
		if (err)
			return err;
		found = true;
	}
	if (!found)
		pr_err("trace not found: %s\n", name);
	return !found;
}

static int __trace_group_enable(trace_group_t *group, int target)
{
	trace_group_t *pos;
	trace_list_t *t;
	int err = 0;

	list_for_each_entry(pos, &group->children, list) {
		err = __trace_group_enable(pos, target);
		if (err)
			return err;
	}

	list_for_each_entry(t, &group->traces, list) {
		err = trace_set_target(t->trace, target);
		if (err)
			return err;
	}

	return 0;
}

/* enable all traces in the group of 'name' */
int trace_group_enable(char *name, int target)
{
	trace_group_t *g = search_trace_group(name);

	if (!g)
		return trace_enable(name, target);

	return __trace_group_enable(g, target);
}

bool trace_analyzer_enabled(analyzer_t *analyzer)
{
	trace_t *t;

	trace_for_each(t) {
		if (TRACE_HAS_ANALYZER(t, free) && trace_is_enable(t))
			return true;
	}
	return false;
}

/* enable 'return value trace' for all function traces */
static void trace_all_set_ret()
{
	trace_t *trace;

	trace_for_each(trace)
	if (trace_is_func(trace))
		trace_set_ret(trace);
}

static bool trace_has_pkt_filter()
{
	pkt_args_t *pkt_args = &trace_ctx.bpf_args.pkt;

	return pkt_args->daddr || pkt_args->addr || pkt_args->saddr ||
	       pkt_args->saddr_v6[0] || pkt_args->daddr_v6[0] ||
	       pkt_args->addr_v6[0]|| pkt_args->sport ||
	       pkt_args->dport|| pkt_args->port||
	       pkt_args->l3_proto || pkt_args->l4_proto;
}

/* By default, don't allow to trace 'all' without any filter condition,
 * as it will cause performance problem.
 */
static int trace_check_force()
{
	bpf_args_t *bpf_args = &trace_ctx.bpf_args;
	trace_args_t *args = &trace_ctx.args;

	if (args->drop || args->force || args->monitor || args->show_traces ||
	    args->rtt)
		return 0;

	if (trace_has_pkt_filter() || bpf_args->pid || bpf_args->first_rtt ||
	    bpf_args->last_rtt ||
	    (args->traces && strcmp(args->traces, "all") != 0) ||
	    args->count)
		return 0;

	return -1;
}
/*根据当前的跟踪模式，对相应的追踪点进行标记*/
static int trace_prepare_mode(trace_args_t *args)
{	
	trace_t *trace;

	switch (trace_ctx.mode) {
	/*1. DIAG ：启用所有挂载点；
	 *   TIMELINE：为 skb_clone 挂载点启用返回值追踪；
	 */
	case TRACE_MODE_DIAG: 
		trace_all_set_ret();
	case TRACE_MODE_TIMELINE:
		if (!trace_ctx.args.traces_noclone) {
			/* enable skb clone trace */
			trace_set_ret(&trace_skb_clone);
		}
		break;

	/*2. LATENCY模式：
	 *   将 skb_clone 挂载点标记为无效，
	 *   原因是当前为延迟模式（latency）
	 */
	case TRACE_MODE_LATENCY:
		//标记无效
		trace_set_invalid_reason(&trace_skb_clone, "latency");
		break;
	/*3. DROP模式：
	 *   启用kfree_skb挂载点
	 */
	case TRACE_MODE_DROP:
		if (!trace_ctx.drop_reason)
			pr_warn("skb drop reason is not support by your kernel"
				", drop reason will not be printed\n");
		if (args->drop_stack) {
			if (trace_set_stack(&trace_kfree_skb))
				goto err;
		}
		trace_set_enable(&trace_kfree_skb);
	/*3.BASIC SOCK
	 *  这两种模式下没有特定的挂载点设置
	 */
	case TRACE_MODE_BASIC:
	case TRACE_MODE_SOCK:
		break;
	/*4.MONITOR
	 *  如果挂载点未启用监控功能（monitor），将其标记为无效
	 *  如果挂载点是函数挂载点，并且设置为 TRACE_MONITOR_EXIT 模式，
	 *  启用返回值追踪（trace_set_ret 和 trace_set_retonly）
	 */
	case TRACE_MODE_MONITOR:
		trace_for_each(trace) {
			if (!trace->monitor) {
				trace_set_invalid_reason(trace, "monitor");
				continue;
			}
			if (!trace_is_func(trace))
				continue;
			switch (trace->monitor) {
			case TRACE_MONITOR_EXIT:
				trace_set_retonly(trace);
				trace_set_ret(trace);
				break;
			default:
				break;
			}
		}
		break;
	/*5. RTT
	 *   启用 tcp_ack_update_rtt 挂载点，用于追踪 RTT
	 */
	case TRACE_MODE_RTT:
		trace_set_enable(&trace_tcp_ack_update_rtt);
		break;
	default:
		pr_err("mode not supported!\n");
		goto err;
	}

	if (!args->ret)
		return 0;
	/*启用返回值追踪*/
	switch (trace_ctx.mode) {
	case TRACE_MODE_BASIC:
		pr_err("return value trace is only supported on "
		       "default and 'diag' mode\n");
		goto err;
	case TRACE_MODE_TIMELINE:
		trace_all_set_ret();
		break;
	case TRACE_MODE_DIAG:
	default:
		break;
	}
	return 0;

err:
	return -EINVAL;
}
/*根据传参来启用指定的trace*/
static int trace_parse_traces(char *traces, int target)
{
	char *tmp, *cur;

	if (!traces)
		return 0;

	tmp = calloc(strlen(traces) + 1, 1);
	strcpy(tmp, traces);
	cur = strtok(tmp, ",");
	while (cur) {
		if (trace_group_enable(cur, target)) {
			free(tmp);
			return -EINVAL;
		}
		cur = strtok(NULL, ",");
	}
	free(tmp);

	return 0;
}

static int parse_tcp_flasg(char *flags_str)
{
	u8 flags = 0;

	while (*flags_str != '\0') {
		switch (*flags_str) {
		case 'S':
			flags |= TCP_FLAGS_SYN;
			break;
		case 'A':
			flags |= TCP_FLAGS_ACK;
			break;
		case 'P':
			flags |= TCP_FLAGS_PSH;
			break;
		case 'R':
			flags |= TCP_FLAGS_RST;
			break;
		case 'F':
			flags |= TCP_FLAGS_FIN;
			break;
		default:
			return -EINVAL;
		}
		flags_str++;
	}
	return flags;
}

static void trace_check_sock_skb()
{
	int mode_mask = 1 << trace_ctx.mode;
	bool require_skb, require_sk;
	trace_t *trace;

	require_skb = mode_mask & TRACE_MODE_SKB_REQUIRE_MASK;
	require_sk = mode_mask & TRACE_MODE_SOCK_REQUIRE_MASK;

	/* disable traces that don't support sk in SOCK_MODE, and disable
	 * traces that don't support skb in !(SOCK_MODE || MONITOR_MODE).
	 */
	trace_for_each_cond(trace, (require_skb && !trace->skb) ||
				   (require_sk && !trace->sk))
			trace_set_invalid_reason(trace, "sock or sk mode");
}

static void trace_prepare_pesudo(trace_args_t *args, bpf_args_t *bpf_args)
{
	if (args->rtt_detail) {
		args->traces = "tcp_ack_update_rtt";
		args->sock = true;
		args->rtt = false;
	}

	if (bpf_args->latency_summary)
		args->latency = true;
}

static void trace_enable_default()
{
	trace_t *trace;

	trace_for_each(trace) {
		if (trace->def)
			trace_set_enable(trace);
	}
}
/*跟踪模式、跟踪点的确定*/
static int trace_prepare_args()
{
	bpf_args_t *bpf_args = &trace_ctx.bpf_args;
	trace_args_t *args = &trace_ctx.args;
	char *traces_stack = args->traces_stack;
	bool fix_trace;
	char *traces;
	int err;
	/*1.伪初始化，针对rtt以及latency_summary模式，进行跟踪点以及参数的预设*/
	trace_prepare_pesudo(args, bpf_args);
	traces = args->traces;

	if (args->basic + args->intel + args->drop + args->sock +
	    args->rtt + args->latency > 1) {
		pr_err("multi-mode specified!\n");
		goto err;
	}
	/*2.设置跟踪模式，一共七种跟踪模式
	 *  将跟踪模式填入trace_ctx.mode 中
	*/
#define ASSIGN_MODE(name, __mode) do {			\
	if (args->name)					\
		trace_ctx.mode = TRACE_MODE_##__mode;	\
} while (0)

	ASSIGN_MODE(basic, BASIC);
	ASSIGN_MODE(intel, DIAG);
	ASSIGN_MODE(sock, SOCK);
	ASSIGN_MODE(monitor, MONITOR);
	ASSIGN_MODE(drop, DROP);
	ASSIGN_MODE(rtt, RTT);
	ASSIGN_MODE(latency, LATENCY);

	trace_ctx.mode_mask = 1 << trace_ctx.mode;
	fix_trace = args->drop || args->rtt;
	/*如果还未指定跟踪点，且不是drop、rtt跟踪模式，则启用默认的140个跟踪点*/
	if (!traces) {
		if (!fix_trace)
			trace_enable_default();
	} else if (strcmp(traces, "?") == 0) {
		/*如果指定了traces，并且包含？，则展示所有跟踪点*/
		args->show_traces = true;
		traces = "all";
	} else {
		/*如果是drop或rtt模式*/
		if (fix_trace) {
			pr_err("can't specify traces in this mode!\n");
			goto err;
		}
		trace_parse_traces(traces, 1);
	}
	
	trace_parse_traces(traces_stack, 2);
	if (!debugfs_mounted()) {
		pr_err("debugfs is not mounted! Please mount it with the "
		       "command: mount -t debugfs debugfs "
		       "/sys/kernel/debug\n");
		goto err;
	}
	/*3.丢包原因模式*/
	if (drop_reason_support()) {
		bpf_args->drop_reason = true;
		trace_ctx.drop_reason = true;
		get_drop_reason(1);
	}
	/*4.输出速率限制*/
	if (bpf_args->rate_limit && (trace_ctx.mode_mask & TRACE_MODE_BPF_CTX_MASK)) {
		pr_err("--rate-limit can't be used in timeline(default)/diag mode\n");
		goto err;
	}
	bpf_args->__rate_limit = bpf_args->rate_limit;
	bpf_args->has_filter = trace_has_pkt_filter();
	/*5.解析过滤和排除规则*/
	trace_parse_traces(args->trace_exclude, 4);
	if (args->trace_matcher) {
		if (!(trace_ctx.mode_mask & TRACE_MODE_BPF_CTX_MASK)) {
			pr_err("--trace-matcher not supported in this mode\n");
			goto err;
		}
		trace_parse_traces(args->trace_matcher, 3);
		bpf_args->match_mode = true;
	}
	/*6.free模式*/
	if (args->trace_free) {
		if (!(trace_ctx.mode_mask & TRACE_MODE_BPF_CTX_MASK)) {
			pr_err("--trace_free not supported in this mode\n");
			goto err;
		}
		trace_parse_traces(args->trace_free, 5);
	}
	/*7.显示延迟模式，只能在上下文模式下启用*/
	if (args->latency_show && !mode_has_context()) {
		pr_err("--latency-show not supported in this mode\n");
		goto err;
	}
	/*8.最小延迟*/
	if (args->min_latency) {
		if (!(trace_ctx.mode_mask & TRACE_MODE_BPF_CTX_MASK)) {
			pr_err("--min-latency is not supported in this mode\n");
			goto err;
		}
		args->latency_show = true;
		bpf_args->latency_min = args->min_latency;
	}

	/* enable tcp_ack_update_rtt as monitor if rtt set 
	 * 启用rtt更新追踪
	*/
	if (bpf_args->first_rtt || bpf_args->last_rtt)
		trace_tcp_ack_update_rtt.monitor = 2;
	/*根据当前的跟踪模式，对相应的追踪点进行标记*/
	if (trace_prepare_mode(args))
		goto err;

	if (!fix_trace)
		trace_check_sock_skb();

	if (args->netns_current) {
		bpf_args->netns = file_inode("/proc/self/ns/net");
		pr_debug("current netns inode is: %u\n", bpf_args->netns);
	}
	/*设置追踪模式*/
	bpf_args->trace_mode = 1 << trace_ctx.mode;
	trace_ctx.detail = bpf_args->detail;
	bpf_args->max_event = args->count;
	trace_ctx.skip_last = !bpf_args->latency_free;

	if (args->pkt_len) {
		u32 len_1, len_2;
		char buf[32];

		if (sscanf(args->pkt_len, "%u-%u%s", &len_1, &len_2,
			buf) == 2) {
			bpf_args->pkt.pkt_len_1 = len_1;
			bpf_args->pkt.pkt_len_2 = len_2;
		} else if (sscanf(args->pkt_len, "%u%s", &len_1,
			buf) == 1) {
			bpf_args->pkt.pkt_len_1 = len_1;
			bpf_args->pkt.pkt_len_2 = len_1;
		} else {
			pr_err("--pkt_len: invalid format. valid format: "
			       "10 or 10-20\n");
			goto err;
		}
	}

	if (args->tcp_flags) {
		err = parse_tcp_flasg(args->tcp_flags);
		if (err < 0) {
			pr_err("--tcp-flags: invalid char, valid chars "
			       "are: SAPR\n");
			goto err;
		}
		bpf_args->pkt.tcp_flags = err;
	}

	if (trace_check_force()) {
		pr_err("\tdon't allow to trace 'all' without any filter condition,\n"
		       "\tas it will cause performance problem.\n\n"
		       "\t** You can use '--force' to skip this check **\n");
		goto err;
	}

	return 0;
err:
	return -1;
}

static void trace_exec_cond()
{
	trace_t *trace;

	trace_for_each(trace) {
		if (trace->cond && execf(NULL, "%s; %s", cond_pre,
					 trace->cond))
			trace_set_invalid_reason(trace, "cond");
	}
}

static void trace_prepare_status()
{
	u32 mode = trace_ctx.mode_mask;
	trace_t *trace;

	trace_for_each(trace) {
		/*含有free或drop分析器的跟踪点会被设置为FUNC_STATUS_FREE状态*/
		if (TRACE_HAS_ANALYZER(trace, free) || TRACE_HAS_ANALYZER(trace, drop))
			trace_set_status(trace->index, FUNC_STATUS_FREE);

		/* in the monitor mode, perfer to trace skb, then sk */
		if (!trace->skb || (mode & (TRACE_MODE_SOCK_MASK | TRACE_MODE_RTT_MASK))) {
			if (trace->sk)
				trace_set_status(trace->index, FUNC_STATUS_SK);
		}
	}
}
/*挂载点初始化,标记有效挂载点*/
static int trace_prepare_traces()
{
	char func[128], name[136];
	trace_t *trace;
	/*1.根据模式启用特定追踪组life*/
	if ((1 << trace_ctx.mode) & TRACE_MODE_BPF_CTX_MASK)
		trace_group_enable("life", 1);//将life组内追踪点启用
	/*2.对每个追踪点进行条件检查，找到未满足条件的追踪点，标记为无效*/
	trace_exec_cond();
	pr_debug("begin to resolve kernel symbol...\n");

	/* make the programs that target kernel function can't be found
	 * load manually.
	 */
	/*3. 遍历所有已启用的追踪点，开始解析内核符号*/
	trace_for_each(trace) {
		/*3.1 跳过标记为无效或未启用的追踪点*/
		if (trace_is_invalid(trace) || !trace_is_enable(trace))
			continue; 
		/*3.2 Tracepoint 挂载路径检查*/
		if (!trace_is_func(trace)) {
			/* For tracepoint, check the exist of the path */
			sprintf(name, "/sys/kernel/debug/tracing/events/%s",
				trace->tp);//name中存着具体的路径
			/*未找到文件，则标记为无效*/
			if (!file_exist(name))
				trace_set_invalid_reason(trace, "tp not found");
			continue;
		}
		/*3.3 跟踪点名称是否在内核符号表中存在
		 *    存在则直接跳过；
		 */
		if (sym_get_type(trace->name) != SYM_NOT_EXIST)
			continue;
		/*3.4 再次检查跟踪点是否是函数类型
		 *    不是函数类型、不是tp，则直接标记为无效跟踪点，跳过
		 */
		if (!trace_is_func(trace)) {
			trace_set_invalid(trace);
			continue;
		}
		/*3.5 去内核符号表中查找与这个函数相关的所有函数是否存在，不存在则标记为无效*/
		sprintf(name, "%s.", trace->name);
		if (sym_search_pattern(name, func, true) == SYM_NOT_EXIST) {
			pr_verb("kernel function %s not founded, skipped\n",
				trace->name);
			trace_set_invalid_reason(trace, "not found");
			continue;
		}
		/*3.6 如果找到该跟踪点相关函数，更新trace结构体,设置为需要手动加载*/
		trace->status |= TRACE_ATTACH_MANUAL;
		strcpy(trace->name, func);
		pr_debug("%s is made manual attach\n", trace->name);
	}

	pr_debug("finished to resolve kernel symbol\n");
	/*4. 设置跟踪点的free和sk状态*/
	trace_prepare_status();
	/*5.预处理追踪点*/
	if (trace_ctx.ops->prepare_traces)
		trace_ctx.ops->prepare_traces();

	return 0;
}
/*遍历所有包含备用trace的备用链，只保留第一个trace有效，其余的均无效*/
static void trace_prepare_backup()
{
	trace_t *trace, *next;

	trace_for_each(trace) {
		bool hitted = false;

		/* find a enabled leader of a backup chain */
		/*1.1 检查当前 trace 是否为备份链中的有效成员
		 *    如果当前 trace 已经是备份（即它已经是某个备份链的成员, trace_ipt_do_table,trace___netif_receive_skb_core）
		 *    如果当前 trace 没有指定备份链(只有__netif_receive_skb_core_pskb和_ipt_do_table_legacy指定了替代跟踪点)
		 *    如果当前 trace 未启用
		 *    跳过该trace
		 */
		if (trace->is_backup || !trace->backup ||
		    !trace_is_enable(trace))
			continue;
		
		/*1.2 满足以上条件，则进入备份链处理+
		 *    遍历备份链，将第一个有效trace标记为有效，其余trace标记为无效
		 */
		next = trace;
		while (next) {
			/* keep the first valid trace and make the others
			 * invalid.
			 */

			/*1.2.1 如果当前备用链中已经有trace被标记，则直接将当前trace标记为无效*/
			if (hitted) {
				trace_set_invalid_reason(next, "backup");
				goto next_bk;
			}

			/*1.2.2 如果当前trace是有效的，并且当前备用链还没有trace被命中，
			 *      则当前trace为备用连中第一个有效点
			 */
			if (!trace_is_invalid(next)) {
				pr_debug("backup: valid prog for %s is %s\n",
					 next->name, next->prog);
				hitted = true;
			}
next_bk:
			next = next->backup;
		}
	}
}

/*打印所有有效的挂载点*/
static void trace_print_enabled()
{
	trace_t *trace;
	char *fmt;

	pr_verb("following traces are enabled and valid:\n");
	trace_for_each(trace) {
		if (!trace_is_usable(trace))
			continue;

		if (trace_is_func(trace)) {
			if (trace_is_ret(trace))
				fmt = "kprobe/kretprobe";
			else
				fmt = "kprobe";
		} else {
			fmt = "tracepoint";
		}
		pr_verb("\t%s: %s, prog: %s, status: 0x%x\n", fmt, trace->name,
			trace->prog, trace_get_status(trace->index));
	}
}
/*遍历所有挂载点,通过比对内核符号表对每个跟踪点进行有效性标记*/
int trace_prepare()
{
	int err, i = 0;
	/*1.BTF支持检查*/
#ifndef NO_BTF
	if (!file_exist("/sys/kernel/btf/vmlinux") && !trace_ctx.args.btf_path) {
		pr_err("BTF is not support by your kernel, please compile"
		       "this tool with \"NO_BTF=1\"\n");
		err = -ENOTSUP;
		goto err;
	}
	if (!kernel_has_config("DEBUG_INFO_BTF_MODULES")) {
		pr_warn("DEBUG_INFO_BTF_MODULES not enabled, some infomation, "
			"such as nf_tables, maybe incorrect\n");
	}
#else
	/*2.内核版本兼容检查*/
	if (strcmp(kernel_version_str(), macro_to_str(__KERN_VER)) != 0) {
		pr_warn("running kernel version(%s) is not compatible with the compile version(%s), "
			"result maybe incorrect!\n",
			kernel_version_str(), macro_to_str(__KERN_VER));
	}
#endif
	/*3.参数准备
	 *  跟踪模式的确定
	 *  跟踪点的确定
	 */
	err = trace_prepare_args();
	if (err)
		goto err;
	/*4.初始化操作集
	 *  遍历trace_ops_all选择支持当前系统的操作集
	 */
	for (; i < ARRAY_SIZE(trace_ops_all); i++) {
		if (trace_ops_all[i]->trace_supported()) {
			set_trace_ops(trace_ops_all[i]);
			break;
		}
	}

	if (i == ARRAY_SIZE(trace_ops_all)) {
		pr_err("no ops found!\n");
		err = -EINVAL;
		goto err;
	}
	/*5.跟踪点有效性的确定，遍历所有跟踪点，确保其有效性*/
	err = trace_prepare_traces();
	if (err)
		goto err;
	/*6.确保以root权限运行*/
	if (geteuid() != 0) {
		pr_err("Please run as root!\n");
		err = -EPERM;
		goto err;
	}
	/*7.检查内核特性*/
	if (trace_ctx.ops->trace_feat_probe) {
		pr_debug("kernel feature probe begin\n");
		trace_ctx.ops->trace_feat_probe();
		pr_debug("kernel feature probe end\n");
	}
	/*8.针对包含备用链的traces，只启用备用链中第一个有校挂载点,其他的备用挂载点标记为无效
	 *  目前只有 ipt_do_table_legacy 和 __netif_receive_skb_core_pskb有备用链，其余跟踪点均没有跟踪链
	 */
	trace_prepare_backup();
	
	/*9. 打印所有跟踪点*/
	if (trace_ctx.args.show_traces) {
		trace_show(&root_group);
		exit(0);
	}

	/*10.打印所有有效挂载点*/
	trace_print_enabled();

	return 0;
err:
	return err;
}
/*遍历所有定义的跟踪点，对无效或未启用的跟踪点禁用其对应的 BPF 程序的自动加载功能*/
int trace_pre_load()
{
	struct bpf_program *prog;
	char kret_name[128];
	trace_t *trace;
	bool autoload;

	/*1.遍历所有追踪点，禁用未启用或无效的追踪点的 BPF 程序*/
	trace_for_each(trace) {

		/*1.1 有效的已启用跟踪点，启用自动加载功能*/
		autoload = !trace_is_invalid(trace) &&
			   trace_is_enable(trace);

		/*1.2 如果需要自动加载且不是返回值追踪点，跳过检查返回值的逻辑*/
		if (autoload && !trace_is_retonly(trace))
			goto check_ret;
			
		/*1.3 根据追踪点的程序名称查找对应的 BPF 程序*/
		prog = bpf_pbn(trace_ctx.obj, trace->prog);
		if (!prog) {
			pr_verb("prog: %s not founded\n", trace->prog);
			continue;
		}

		/*1.4 设置该程序不自动加载*/
		bpf_program__set_autoload(prog, false);
		pr_debug("prog: %s is made no-autoload\n", trace->prog);

check_ret:
		/*1.5 检查是否为函数类型的追踪点，或者需要处理返回值的追踪点 */
		if (!trace_is_func(trace) || (trace_is_ret(trace) &&
		    autoload))
			continue;

		sprintf(kret_name, "ret%s", trace->prog);
		/*1.6 查找对应的返回值追踪点的 BPF 程序*/
		prog = bpf_pbn(trace_ctx.obj, kret_name);
		if (!prog) {
			pr_verb("prog: %s not founded\n", kret_name);
			continue;
		}
		/*1.7 设置返回值追踪点程序不自动加载 */
		bpf_program__set_autoload(prog, false);
		pr_debug("ret prog: %s is made no-autoload\n", trace->prog);
	}

	return 0;
}

static int trace_bpf_load()
{
	/* skel is already opened */
	if (trace_ctx.obj)
		return 0;

	if (liberate_l())
		pr_warn("failed to set rlimit\n");

	return trace_ctx.ops->trace_load();
}
/*根据不同模式初始化操作集*/
static void trace_prepare_ops()
{
	/*1.根据配置，决定是否启用函数调用统计功能
	 * trace_ctx.bpf_args.func_stats：指定是否启用函数调用统计功能
	 * func_stats_poll_handle函数会定期从ebpf map中读取统计数据;
	 */
	if (trace_ctx.bpf_args.func_stats) {
		trace_ctx.ops->raw_poll = func_stats_poll_handler;
		return;
	}
	
	/*2.不需要统计功能,根据mod模式匹配对应的trace_poll或raw_poll函数
	*/
	switch (trace_ctx.mode) {
	case TRACE_MODE_BASIC:
	case TRACE_MODE_DROP:
	case TRACE_MODE_MONITOR:
		trace_ctx.ops->trace_poll = basic_poll_handler;
		break;
	case TRACE_MODE_SOCK:
		trace_ctx.ops->trace_poll = async_poll_handler;
		break;
	case TRACE_MODE_DIAG:
	case TRACE_MODE_TIMELINE:
		trace_ctx.ops->trace_poll = ctx_poll_handler;
		break;
	case TRACE_MODE_LATENCY:
		if (trace_ctx.bpf_args.latency_summary)
			trace_ctx.ops->raw_poll = stats_poll_handler;
		else
			trace_ctx.ops->trace_poll = latency_poll_handler;
		break;
	case TRACE_MODE_RTT:
		trace_ctx.ops->raw_poll = stats_poll_handler;
	default:
		break;
	}
}
/*加载并附加eBPF程序*/
int trace_bpf_load_and_attach()
{
	/*1.load_bpf*/
	if (trace_bpf_load())
		goto err;

	pr_debug("begin to attach eBPF program...\n");
	/*2.attach bpf*/
	if (trace_ctx.ops->trace_attach()) {
		trace_ctx.ops->trace_close();
		goto err;
	}
	pr_debug("eBPF program attached successfully\n");
	/*3.准备ops操作函数*/
	trace_prepare_ops();

	return 0;
err:
	return -1;
}

static void trace_on_lost(void *ctx, int cpu, __u64 cnt)
{
	pr_err("event losting happened, this can happen when the packets"
	       "we trace are too many.\n"
	       "Please add some filter argument (such as ip or port) to "
	       "prevent this happens.\n");
	exit(-1);
}

static inline void poll_handler_wrap(void *ctx, int cpu, void *data,
				     u32 size)
{
	/*1.判断是否停止跟踪*/
	if (trace_stopped())
		return;
	/*2.调用 trace_poll 函数完成具体的数据处理
	 *  具体实现依赖于 trace_ctx.ops
	*/
	trace_ctx.ops->trace_poll(ctx, cpu, data, size);//一个指向具体处理函数的指针；
}

static u8 bpf_args_buf[CONFIG_MAP_SIZE];
bpf_args_t *get_bpf_args()
{
	bpf_args_t *args = (void *)bpf_args_buf;
	int map_fd, key = 0;
	struct bpf_map *map;

	map = bpf_object__find_map_by_name(trace_ctx.obj, "m_config");
	map_fd = bpf_map__fd(map);
	bpf_map_lookup_elem(map_fd, &key, bpf_args_buf);
	return args;
}

static int poll_timeout(int err)
{
	if (trace_ctx.stop)
		return 1;

	if (err == 0 && trace_ctx.args.count) {
		if (trace_ctx.args.count <= get_bpf_args()->event_count) {
			usleep(200000);
			return 1;
		}

		return 0;
	}
	return 0;
}

int trace_poll()
{
	struct perf_buffer *pb;
	int err, map_fd;

	if (trace_ctx.ops->raw_poll) {
		trace_ctx.ops->trace_ready();//该函数在tracepoint或kprobe对应的文件中有定义；
		return trace_ctx.ops->raw_poll();
	}
	/*1.获取map描述符*/
	map_fd = bpf_object__find_map_fd_by_name(trace_ctx.obj, "m_event");
	if (!map_fd)
		return -1;

#if defined(LIBBPF_MAJOR_VERSION) && (LIBBPF_MAJOR_VERSION >= 1)
	/*2.创建perf_buffer 用于监听eBPF程序的输出；
	 *  poll_handler_wrap函数根据指定的模式进行数据的聚合与分析；
	 *  trace_on_lost 用于处理丢失事件的回调函数；
	 */
	pb = perf_buffer__new(map_fd, 1024, poll_handler_wrap,
			      trace_on_lost, NULL, NULL);
#else
	struct perf_buffer_opts pb_opts = {
		.sample_cb = poll_handler_wrap,
		.lost_cb = trace_on_lost,
	};
	/*创建*/
	pb = perf_buffer__new(map_fd, 1024, &pb_opts);
#endif
	/*3. 检查perf buffer是否创建成功*/
	err = libbpf_get_error(pb);
	if (err) {
		pr_err("failed to setup perf_buffer: %d\n", err);
		return err;
	}

	trace_ctx.ops->trace_ready();
	/*4.开始监听数据
	 *  调用perf_buffer__poll 监听数据,每次有数据进来，都会触发回调函数poll_handler_wrap；
	*/
	while ((err = perf_buffer__poll(pb, 1000)) >= 0) {
		if (poll_timeout(err))
			break;
	}
	return 0;
}
