import { defineConfig } from "tsup";

export default defineConfig({
  entry: {
    index: "src/index.ts",
    "middleware/express": "src/middleware/express.ts",
    "middleware/hono": "src/middleware/hono.ts",
    "adapters/mcp": "src/adapters/mcp.ts",
    "adapters/protected-resource": "src/adapters/protected-resource.ts",
  },
  format: ["esm", "cjs"],
  dts: true,
  sourcemap: true,
  clean: true,
  splitting: true,
  treeshake: true,
  external: ["express", "hono"],
  target: "node18",
});
