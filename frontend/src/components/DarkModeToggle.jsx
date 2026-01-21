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
      className="dark-mode-toggle"
      title="Toggle dark mode"
      onClick={() => setDarkMode(!darkMode)}
      aria-label="Toggle dark mode"
      type="button"
    >
      <span className="icon">{darkMode ? "☀️" : "🌙"}</span>
    </button>
  );
}
