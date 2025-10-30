# 项目简介

该项目是一个基于 Vite + React + TypeScript 构建的 Web 工具，提供类似 Postman 的「粘贴 cURL 命令 → 解析 → 可视化编辑 → 发起 HTTP 请求」体验，帮助开发者快速从命令行请求迁移到图形化调试环境。

## 功能特性

- **cURL 导入解析**：使用 `curlconverter` 库将原始 cURL 文本转换为结构化请求信息，并提示潜在解析警告。
- **模块化请求编辑**：按模块展示请求方法、协议、主机、路径、查询参数、请求头、请求体（JSON/文本/表单）、认证信息等，支持增删改与启用开关。
- **请求执行与响应展示**：内置 `fetch` 发送请求，显示状态码、耗时、响应头与响应体（自动 JSON 格式化）。
- **错误反馈与重置**：解析失败、请求异常时给出中文提示，可一键重置当前会话。

核心实现位于 `src/App.tsx`，主要逻辑包含：

- `toJsonObjectWarn`：负责 cURL → JSON 解析及警告收集。
- `convertCurlJsonToState`：将解析结果映射为页面可编辑的请求状态。
- `sendRequest`：汇总用户编辑后的请求配置并调用 `fetch` 发起请求。
- 各类输入组件与状态更新函数用于同步 UI 与请求数据。

样式定义集中在 `src/index.css` 与 `src/App.css`，采用纯 CSS 实现分栏布局、模块卡片与响应展示。

## 快速开始

### 环境要求

- Node.js ≥ 18
- npm ≥ 9

### 安装依赖

```bash
npm install
```

### 开发调试

```bash
npm run dev
```

启动后访问终端提示的本地地址，在浏览器中测试 cURL 导入与请求功能。

### 构建产物

```bash
npm run build
```

构建结果输出在 `dist/` 目录，可直接部署到静态资源服务器。

### 预览生产构建（可选）

```bash
npm run preview
```

该命令以本地服务器方式预览打包后的页面，便于上线前确认效果。

## Docker 部署

项目提供基于 Nginx 的容器化部署方案。

### 构建镜像

```bash
docker build -t curl-converter:latest .
```

此命令将执行前端构建并输出 Nginx 静态站点镜像。

### 运行容器

```bash
docker run --rm -p 8080:80 curl-converter:latest
```

启动后可通过 `http://localhost:8080` 访问，若需要自定义端口或域名，可调整 `docker run` 的 `-p` 映射。
