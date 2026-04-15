import { ScenarioPage } from "@/components/scenarios/ScenarioPage";
import federated from "@/lib/scenarios/federated.json";
import { Scenario } from "@/lib/types";

export default function FederatedPage() {
  return <ScenarioPage scenario={federated as unknown as Scenario} />;
}
