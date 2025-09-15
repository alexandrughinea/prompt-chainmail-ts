import { PromptChainmail, Rivets } from "../dist/prompt-chainmail.es.js";
import { readFileSync } from "fs";

async function runInstructionHijackingExample() {
  console.log("instructionHijacking (80% confidence filter)\n");

  const input = readFileSync("./example_5.md", "utf-8");
  console.log("Input:");
  console.log("-".repeat(50));
  console.log(input);
  console.log("-".repeat(50));
  console.log();

  const chainmail = new PromptChainmail()
    .forge(Rivets.instructionHijacking())
    .forge(Rivets.confidenceFilter(0.8));

  try {
    const result = await chainmail.protect(input);

    console.log("Protection Result:", result);

    if (result.error) {
      console.log(`Error: ${result.error}`);
    }
  } catch (error) {
    console.log(`Error: ${error.message}`);
  }
}

runInstructionHijackingExample().catch(console.error);
