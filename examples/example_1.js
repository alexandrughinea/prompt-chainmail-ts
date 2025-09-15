import { PromptChainmail, Rivets } from "../dist/prompt-chainmail.es.js";
import { readFileSync } from "fs";

async function runSqlInjectionExample() {
  console.log("sqlInjection (80% confidence filter)\n");

  const input = readFileSync("./example_1.md", "utf-8");
  console.log("Input:");
  console.log("-".repeat(50));
  console.log(input);
  console.log("-".repeat(50));
  console.log();

  const chainmail = new PromptChainmail()
    .forge(Rivets.sqlInjection())
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

runSqlInjectionExample().catch(console.error);
