# @pondpilot/flowscope-react

React components for visualizing FlowScope lineage results.

This is a private monorepo workspace shared by the FlowScope app and VS Code extension. It is
not published to npm.

## Overview

This package provides ready-to-use React components for rendering interactive lineage graphs and SQL editors integrated with FlowScope analysis results.

## Development

```bash
yarn workspace @pondpilot/flowscope-react build
```

## Usage

```tsx
import { LineageExplorer } from '@pondpilot/flowscope-react';

// ...
<LineageExplorer result={analysisResult} />
```

See the root [README](../../README.md) for more details.

## Store hooks

`LineageProvider` continues to support the structured `useLineage()` API. For
components that only need part of the store, use selector-based state and
action hooks so unrelated updates do not rerender the component:

```tsx
const selectedNodeId = useLineageState((state) => state.selectedNodeId);
const selectNode = useLineageActions((actions) => actions.selectNode);
```

Calling `useLineageState()` or `useLineageActions()` without a selector remains
supported. Their returned objects are referentially stable until a selected
state field or action changes.
