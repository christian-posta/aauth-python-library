import { Scenario } from "@/lib/types";

export async function loadScenario(id: string): Promise<Scenario | null> {
  try {
    // Dynamic import of the JSON fixture
    const data = await import(`@/lib/scenarios/${id}.json`);
    return data.default as Scenario;
  } catch {
    return null;
  }
}
