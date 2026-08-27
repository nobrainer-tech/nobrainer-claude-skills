import path from "path";
import { fileURLToPath } from "url";

const currentDirectory = path.dirname(fileURLToPath(import.meta.url));
const skillsDirectory = path.resolve(currentDirectory, "../../skills");

export const NoBrainerTechSkillsPlugin = async () => ({
  config: async (config) => {
    config.skills = config.skills || {};
    config.skills.paths = config.skills.paths || [];
    if (!config.skills.paths.includes(skillsDirectory)) {
      config.skills.paths.push(skillsDirectory);
    }
  },
});

export default NoBrainerTechSkillsPlugin;
