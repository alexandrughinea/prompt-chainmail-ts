import { Chainmails } from "../dist/prompt-chainmail.es.js";
import { readFileSync } from "fs";

async function runChainmailExamples() {
  console.log("chainmails\n");

  const input = readFileSync("./example_6.md", "utf-8");
  console.log("Input:");
  console.log("-".repeat(50));
  console.log(input);
  console.log("-".repeat(50));
  console.log();

  const chainmails = [
    { name: "Basic", instance: Chainmails.basic() },
    { name: "Advanced", instance: Chainmails.advanced() },
    { name: "Strict", instance: Chainmails.strict() },
    { name: "Development", instance: Chainmails.development() },
  ];

  for (const { name, instance } of chainmails) {
    console.log(`Testing with ${name} Chainmail:`);
    console.log("-".repeat(30));

    try {
      const result = await instance.protect(input);

      console.log("Protection Result:", result);

      if (result.error) {
        console.log(`Error: ${result.error}`);
      }
    } catch (error) {
      console.log(`Error: ${error.message}`);
    }

    console.log();
  }
}

runChainmailExamples().catch(console.error);
