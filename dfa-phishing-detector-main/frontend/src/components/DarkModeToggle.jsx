import { useEffect, useState } from "react";
import "./DarkModeToggle.css";

export default function DarkModeToggle() {
  const [darkMode, setDarkMode] = useState(false);

  useEffect(() => {
    if (darkMode) {
      document.body.classList.add("dark-mode");
    } else {
      document.body.classList.remove("dark-mode");
    }
  }, [darkMode]);

  return (
   <button
  className={`dark-toggle ${darkMode ? "active" : ""}`}
  title="Toggle dark mode"
  onClick={() => setDarkMode(!darkMode)}
  aria-label="Toggle dark mode"
>

      <span className="icon sun">☀️</span>
      <span className="icon moon">🌙</span>
      <span className="toggle-thumb" />
    </button>
  );
}
