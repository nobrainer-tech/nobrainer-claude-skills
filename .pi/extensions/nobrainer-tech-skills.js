import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const BOOTSTRAP_MARKER = "NOBRAINER_BOOTSTRAP_V1";
const extensionDirectory = dirname(fileURLToPath(import.meta.url));
const packageRoot = resolve(extensionDirectory, "../..");
const skillsDirectory = resolve(packageRoot, "skills");
const bootstrapPath = resolve(packageRoot, "adapters", "bootstrap.md");

let cachedBootstrap;

export default function NoBrainerTechSkillsPiExtension(pi) {
  let injectBootstrap = true;

  pi.on("resources_discover", async () => ({ skillPaths: [skillsDirectory] }));
  pi.on("session_start", async () => { injectBootstrap = true; });
  pi.on("session_compact", async () => { injectBootstrap = true; });

  pi.on("context", async (event) => {
    // Context changes are ephemeral, so keep the gate enabled for each prompt.
    // The marker prevents duplicate injection within one prompt or compaction.
    if (!injectBootstrap || event.messages.some(messageContainsBootstrap)) return;
    const bootstrap = getBootstrap();
    const message = {
      role: "user",
      content: [{ type: "text", text: bootstrap }],
      timestamp: Date.now(),
    };
    const index = firstNonCompactionSummaryIndex(event.messages);
    return {
      messages: [
        ...event.messages.slice(0, index),
        message,
        ...event.messages.slice(index),
      ],
    };
  });
}

function getBootstrap() {
  if (cachedBootstrap === undefined) {
    cachedBootstrap = readFileSync(bootstrapPath, "utf8");
  }
  return cachedBootstrap;
}

function messageContainsBootstrap(message) {
  const content = message?.content;
  if (typeof content === "string") return content.includes(BOOTSTRAP_MARKER);
  if (!Array.isArray(content)) return false;
  return content.some(
    (part) => part?.type === "text" && part.text?.includes(BOOTSTRAP_MARKER),
  );
}

function firstNonCompactionSummaryIndex(messages) {
  let index = 0;
  while (messages[index]?.role === "compactionSummary") index += 1;
  return index;
}
