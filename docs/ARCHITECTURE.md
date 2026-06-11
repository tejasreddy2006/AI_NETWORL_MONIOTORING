# Architecture Overview

> For the full implementation plan and detailed architecture, see the [Implementation Plan](../implementation_plan.md).

## System Architecture

NetGuard AI follows a modern microservices-inspired architecture with clear separation of concerns.

### High-Level Components

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   Frontend   │────▶│   Backend    │────▶│   Database   │
│  React SPA   │     │  Flask API   │     │    MySQL     │
│  + Vite      │     │  + SocketIO  │     │   + Redis    │
└──────────────┘     └──────────────┘     └──────────────┘
                           │
                     ┌─────┴─────┐
                     │           │
               ┌─────▼───┐ ┌────▼────┐
               │   ML    │ │  Ollama  │
               │ Engine  │ │   AI     │
               └─────────┘ └─────────┘
```

_Full architecture documentation in progress..._
