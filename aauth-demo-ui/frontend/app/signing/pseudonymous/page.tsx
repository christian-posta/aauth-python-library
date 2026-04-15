import { ScenarioPage } from "@/components/scenarios/ScenarioPage";
import pseudonymous from "@/lib/scenarios/pseudonymous.json";
import { Scenario } from "@/lib/types";

export default function PseudonymousPage() {
  return <ScenarioPage scenario={pseudonymous as unknown as Scenario} />;
}
