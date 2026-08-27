import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "url";

const currentDirectory = path.dirname(fileURLToPath(import.meta.url));
const skillsDirectory = path.resolve(currentDirectory, "../../skills");
const bootstrapPath = path.resolve(currentDirectory, "../../adapters/bootstrap.md");
const bootstrapMarker = "NOBRAINER_BOOTSTRAP_V1";
let bootstrapCache;

const getBootstrap = () => {
  if (bootstrapCache === undefined) {
    bootstrapCache = readFileSync(bootstrapPath, "utf8");
  }
  return bootstrapCache;
};

export const NoBrainerTechSkillsPlugin = async () => ({
  config: async (config) => {
    config.skills = config.skills || {};
    config.skills.paths = config.skills.paths || [];
    if (!config.skills.paths.includes(skillsDirectory)) {
      config.skills.paths.push(skillsDirectory);
    }
  },
  "experimental.chat.messages.transform": async (_input, output) => {
    if (!Array.isArray(output.messages)) return;
    const firstUser = output.messages.find((message) => message.info?.role === "user");
    if (!firstUser || !Array.isArray(firstUser.parts) || firstUser.parts.length === 0) {
      return;
    }
    const textPart = firstUser.parts.find(
      (part) => part.type === "text" && typeof part.text === "string",
    );
    if (!textPart || textPart.text.includes(bootstrapMarker)) return;
    textPart.text = `${getBootstrap().trimEnd()}\n\n${textPart.text}`;
  },
});

export default NoBrainerTechSkillsPlugin;
