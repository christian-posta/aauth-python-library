import { ScenarioPage } from "@/components/scenarios/ScenarioPage";
import data from "@/lib/scenarios/missions-resource-access.json";
import { Scenario } from "@/lib/types";
export default function Page() { return <ScenarioPage scenario={data as unknown as Scenario} />; }
