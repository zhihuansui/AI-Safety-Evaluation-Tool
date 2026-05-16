AI Safety Evaluation Tool

轻量级本地 LLM 安全评测工具，支持 5 类攻击 + 6 层防御，自动生成报告。

========================================

前置条件

- Python 3.9+
- Ollama 已安装并运行
- 至少一个测试模型（如 gemma4:latest、gemma3:latest）

========================================

安装依赖

pip install openai pyyaml

========================================

攻击类型

- 提示注入
- 敏感信息披露
- 不当输出处理（越狱）
- 过度代理
- 系统提示泄露

内置 30+ 攻击模板，位于 templates/ 目录，可自由增删。

========================================

防御策略（可任意组合）

- 输入过滤：阻断黑名单关键词
- 输出审查：拦截敏感信息泄露
- 提示加固：追加安全声明
- 三明治防御：前后包裹安全提醒
- XML 封装：用户输入降级为纯文本
- 随机外壳：动态提醒模板

========================================

项目结构

ai-safety-eval/
├── main.py                 主程序入口
├── attacker.py             Ollama 模型调用封装
├── defense_manager.py      六层防御管理器
├── report_generator.py     报告生成模块
├── config.yaml             配置文件
├── requirements.txt        依赖列表
├── templates/              攻击模板库（YAML）
│   ├── prompt_injection.yaml
│   ├── sensitive_disclosure.yaml
│   ├── unsafe_output.yaml
│   ├── excessive_agency.yaml
│   └── system_prompt_leak.yaml
└── README.md

========================================

免责声明：

本工具仅供授权安全测试与学术研究使用，禁止非法用途。