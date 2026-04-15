import { ScenarioPage } from "@/components/scenarios/ScenarioPage";
import identity from "@/lib/scenarios/identity.json";
import { Scenario } from "@/lib/types";

export default function IdentityPage() {
  return <ScenarioPage scenario={identity as unknown as Scenario} />;
}
