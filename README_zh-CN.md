# CADScanner

英文版：[README.md](./README.md)

CADScanner 是一个面向 AutoLISP、FAS 和 VLX 文件的 Go 静态分析工具。本仓库提供用于 CAD 自动化安全分析的项目代码，重点围绕核心分析链路与可复现的命令行工作流。

## 项目说明

CADScanner 面向 CAD 自动化脚本与打包扩展的安全分析场景。它能够解析 AutoLISP 家族输入，统一源码与编译格式的表示，构建中间表示，并识别文件访问、命令执行、持久化逻辑、混淆行为等可疑能力。项目适用于恶意样本初筛、基于规则的解释性分析，以及需要本地 CLI 的研究流程。

## 范围

- 解析并规范化 AutoLISP 家族输入
- 构建面向安全分析的 IR，并提升行为效果
- 检测可疑行为并映射到 ATT&CK 风格技术
- 通过单一 CLI 输出文本或 JSON 分析结果

## 仓库结构

```text
cadscanner/
|- main.go
|- configs/
|- cmd/
|- pkg/
|- examples/
|- README.md
`- README_zh-CN.md
```

## 构建

```bash
go build .
```

## 测试

```bash
go test ./...
```

## 用法

```bash
cadscanner examples/benign.lsp
cadscanner -format json examples/suspicious.lsp
cadscanner -config config.yaml examples/benign.lsp
go run ./cmd/inspect examples/suspicious.lsp
go run ./cmd/batcheval -root examples -format human
```

## 公开命令

- `cadscanner`：主分析 CLI，支持 `.lsp`、`.fas`、`.vlx`
- `batcheval`：对样本目录执行批量评估
- `decompile`：将 `.fas` 和 `.vlx` 反编译为 pseudo-LISP 输出
- `inspect`：单样本诊断命令，用于查看 effects、规则命中和 ATT&CK 结果
- `fasresources`：检查 FAS 中提取出的资源表
- `vlxdiag`：检查 VLX 记录结构及恢复出的元数据

## 研究命令

- `paperexp`：面向论文复现的重放与参数校准流程
- `apisufficiency`：评估 FAS/VLX 恢复表示在 API 遮蔽下的鲁棒性
- `recoveryval`：针对源码/编译文件配对期望做恢复验证
- `llmmetrics`：评估 LLM 缓存与融合效果；需要启用 LLM 的配置

这些命令为了复现和评测而保留，但不属于主要的对外 CLI 接口。

## 配置

如果你需要准备本地配置，可以从 `configs/config.example.yaml` 开始。对于可选的 LLM 分析，请优先通过环境变量提供凭据，不要把真实密钥写进版本控制文件。

## 当前状态

当前项目提供一组公开命令，用于分析与格式检查，同时保留单独的研究命令组以支持论文复现和评测流程。

## 许可证

GNU Affero General Public License v3.0（AGPL-3.0）
