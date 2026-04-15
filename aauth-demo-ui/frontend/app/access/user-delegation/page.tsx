import { ScenarioPage } from "@/components/scenarios/ScenarioPage";
import userDelegation from "@/lib/scenarios/user-delegation.json";
import { Scenario } from "@/lib/types";

export default function UserDelegationPage() {
  return <ScenarioPage scenario={userDelegation as unknown as Scenario} />;
}
