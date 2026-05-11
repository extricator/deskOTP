// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

import { useState, useCallback, useEffect } from "react";
import { SetSetting } from "../../wailsjs/go/main/App";

type Density = "compact" | "default" | "comfortable";

function getInitialDensity(): Density {
  const stored = localStorage.getItem("density");
  if (stored === "compact" || stored === "comfortable") return stored;
  return "default";
}

export function useDensity() {
  const [density, setDensityState] = useState<Density>(getInitialDensity);

  useEffect(() => {
    const html = document.documentElement;
    if (density === "default") {
      html.removeAttribute("data-density");
    } else {
      html.setAttribute("data-density", density);
    }
    localStorage.setItem("density", density);
    SetSetting("density", density).catch(() => {});
  }, [density]);

  const setDensity = useCallback((d: Density) => {
    setDensityState(d);
  }, []);

  return { density, setDensity };
}
