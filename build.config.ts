import { defineBuildConfig } from "obuild/config";

export default defineBuildConfig({
  entries: [
    {
      type: "bundle",
      input: ["./src/index.ts", "./src/utils/index.ts"],
      rolldown: {
        platform: "neutral",
      },
    },
  ],
});
