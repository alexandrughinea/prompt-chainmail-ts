import { PromptChainmail, Rivets } from "../dist/prompt-chainmail.es.js";
import { readFileSync } from "fs";

async function runCodeInjectionExample() {
  console.log("codeInjection  (80% confidence filter)\n");

  const input = readFileSync("./example_3.md", "utf-8");
  console.log("Input:");
  console.log("-".repeat(50));
  console.log(input);
  console.log("-".repeat(50));
  console.log();

  const chainmail = new PromptChainmail()
    .forge(Rivets.codeInjection())
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

runCodeInjectionExample().catch(console.error);
