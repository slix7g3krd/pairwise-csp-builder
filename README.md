# pairwise-csp-builder

安全团队要求全站上 CSP 后，策略生成器反而放大了 XSS：`default-src *` 直接放开；`script-src 'unsafe-inline'` 让内联脚本继续执行；`'unsafe-eval'` 允许字符串求值；`data:` 和 `blob:` 被加进脚本源；nonce 用固定值或时间戳，能预测；策略里缺少 `object-src 'none'`；`frame-ancestors` 没设，点击劫持照旧；报告地址用用户输入，能外带数据；重复指令后写的覆盖前写的；合并策略时把严格项降级。security/csp_builder.py 是核心，tests/test_csp_builder.py 15个红。要修的是：默认拒绝；禁 unsafe-inline；禁 unsafe-eval；脚本源白名单；nonce 高熵；object-src none；frame-ancestors none；报告地址固定；指令去重；合并取严。

## 运行

```bash
python -m pytest tests -q
```

初始状态：15 个用例失败。修复实现使全部用例通过，不要修改 `tests/` 下的测试。

子方向：其他；任务类型：Bugfix；语言/框架：Python 3, pytest；环境可复现等级：无外部依赖。
