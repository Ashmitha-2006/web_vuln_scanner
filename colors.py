class Colors:
    GREEN  = "\033[92m"
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"

    @classmethod
    def severity(cls, sev: str) -> str:
        return {
            "HIGH":   cls.RED,
            "MEDIUM": cls.YELLOW,
            "LOW":    cls.GREEN,
            "INFO":   cls.CYAN,
        }.get(sev, cls.RESET)
