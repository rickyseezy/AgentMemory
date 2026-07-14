import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { App } from "./App";
import { consumeSetupCapability } from "./setup/capability";
import { HttpSetupTransport } from "./setup/http-transport";
import "./styles.css";

const root = document.querySelector<HTMLElement>("#root");
if (root === null) {
  throw new Error("setup root is unavailable");
}

const capability = consumeSetupCapability(window.location, window.history);
const transport = new HttpSetupTransport();

createRoot(root).render(
  <StrictMode>
    <App capability={capability} transport={transport} />
  </StrictMode>,
);
