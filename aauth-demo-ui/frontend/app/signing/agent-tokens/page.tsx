import { ScenarioPage } from "@/components/scenarios/ScenarioPage";
import data from "@/lib/scenarios/delegation.json";
import { Scenario } from "@/lib/types";
export default function Page() { return <ScenarioPage scenario={data as unknown as Scenario} />; }
