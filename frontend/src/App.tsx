import { useQuery } from "@tanstack/react-query";
import { apiFetch } from "./lib/api";

function App() {
  return (
    <>
      <HealthCheck />
    </>
  );
}

export default App;

export function HealthCheck() {
  const { data, isLoading } = useQuery({
    queryKey: ["health"],
    queryFn: () => apiFetch("/health"),
  });

  if (isLoading) return <p>Loading...</p>;

  return <pre>hi {JSON.stringify(data)}</pre>;
}
