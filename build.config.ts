import { defineBuildConfig } from "obuild/config";

export default defineBuildConfig({
  entries: [
    {
      type: "bundle",
      input: [
        "./src/index.ts",
        "./src/compare.ts",
        "./src/entropy.ts",
        "./src/generate.ts",
        "./src/hash.ts",
        "./src/hkdf.ts",
        "./src/hmac.ts",
        "./src/otp.ts",
        "./src/random.ts",
        "./src/sanitize.ts",
        "./src/uuid.ts",
        "./src/utils/index.ts",
      ],
      rolldown: {
        platform: "neutral",
      },
    },
  ],
});
