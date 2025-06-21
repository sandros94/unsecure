import { defineBuildConfig } from "unbuild";

export default defineBuildConfig({
  entries: [
    "./src/index",
    {
      input: "./src/utils",
      outDir: "./dist/utils",
      name: "utils",
    },
  ],
  declaration: true,
  rollup: {
    emitCJS: false,
  },
});
