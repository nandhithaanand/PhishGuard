import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import csv

from url_analyzer import analyze_url
from risk_engine import calculate_risk


class PhishingCheckerApp:

    def __init__(self, root):
        self.root = root
        self.root.title("Phishing Detection & URL Safety Checker")
        self.root.geometry("800x620")
        self.root.configure(bg="#f4f7fb")

        self.last_result = None

        # Simple theme
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", rowheight=28, font=("Arial", 10))
        style.configure("Treeview.Heading", font=("Arial", 10, "bold"))

        # Header
        header = tk.Frame(root, bg="#17365d", height=95)
        header.pack(fill="x")
        header.pack_propagate(False)

        tk.Label(
            header,
            text="🛡 PhishGuard",
            font=("Arial", 22, "bold"),
            bg="#17365d",
            fg="white"
        ).pack(pady=(15, 2))

        tk.Label(
            header,
            text="Phishing Detection & URL Safety Checker",
            font=("Arial", 10),
            bg="#17365d",
            fg="#dbe7f5"
        ).pack()

        # Input section
        input_frame = tk.Frame(root, bg="#f4f7fb")
        input_frame.pack(pady=18)

        tk.Label(
            input_frame,
            text="Enter URL",
            font=("Arial", 11, "bold"),
            bg="#f4f7fb",
            fg="#17365d"
        ).pack()

        row = tk.Frame(input_frame, bg="#f4f7fb")
        row.pack(pady=8)

        self.url_entry = tk.Entry(
            row,
            width=58,
            font=("Arial", 11),
            relief="solid",
            bd=1
        )
        self.url_entry.pack(side=tk.LEFT, ipady=7)

        tk.Button(
            row,
            text="Check URL",
            command=self.check_url,
            bg="#17365d",
            fg="white",
            font=("Arial", 10, "bold"),
            relief="flat",
            padx=12,
            pady=7
        ).pack(side=tk.LEFT, padx=6)

        tk.Button(
            row,
            text="Clear",
            command=self.clear,
            font=("Arial", 10),
            relief="flat",
            padx=12,
            pady=7
        ).pack(side=tk.LEFT)

        # Risk result
        self.result_label = tk.Label(
            root,
            text="Risk Score: -   |   Level: -",
            font=("Arial", 16, "bold"),
            bg="white",
            fg="#17365d",
            padx=20,
            pady=12,
            relief="solid",
            bd=1
        )
        self.result_label.pack(fill="x", padx=30, pady=5)

        # Analysis table
        tk.Label(
            root,
            text="Security Analysis",
            font=("Arial", 12, "bold"),
            bg="#f4f7fb",
            fg="#17365d"
        ).pack(pady=(12, 5))

        table_frame = tk.Frame(root, bg="#f4f7fb")
        table_frame.pack(fill="both", expand=True, padx=30)

        columns = ("Feature", "Detected")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings")

        self.tree.heading("Feature", text="Feature")
        self.tree.heading("Detected", text="Detected")
        self.tree.column("Feature", width=350)
        self.tree.column("Detected", width=180, anchor="center")

        scrollbar = ttk.Scrollbar(
            table_frame,
            orient="vertical",
            command=self.tree.yview
        )
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Reasons
        tk.Label(
            root,
            text="Warnings / Reasons",
            font=("Arial", 11, "bold"),
            bg="#f4f7fb",
            fg="#17365d"
        ).pack(pady=(10, 3))

        self.reasons_list = tk.Listbox(
            root,
            width=80,
            height=5,
            font=("Arial", 10),
            relief="solid",
            bd=1
        )
        self.reasons_list.pack(padx=30, pady=(0, 8), fill="x")

        # Export buttons
        button_frame = tk.Frame(root, bg="#f4f7fb")
        button_frame.pack(pady=(0, 8))

        tk.Button(
            button_frame,
            text="Export TXT",
            command=self.export_txt,
            font=("Arial", 9, "bold"),
            padx=10
        ).pack(side=tk.LEFT, padx=4)

        tk.Button(
            button_frame,
            text="Export CSV",
            command=self.export_csv,
            font=("Arial", 9, "bold"),
            padx=10
        ).pack(side=tk.LEFT, padx=4)

        tk.Label(
            root,
            text="Offline analysis • The URL is not opened",
            font=("Arial", 8),
            bg="#f4f7fb",
            fg="#777777"
        ).pack(pady=(0, 8))

    def check_url(self):
        url = self.url_entry.get().strip()

        if not url:
            messagebox.showwarning("Warning", "Please enter a URL.")
            return

        p1_result = analyze_url(url)
        score, level, reasons = calculate_risk(p1_result)

        self.last_result = (url, p1_result, score, level, reasons)

        for item in self.tree.get_children():
            self.tree.delete(item)

        for feature, detected in p1_result.items():
            status = "YES" if detected else "NO"
            self.tree.insert("", tk.END, values=(feature, status))

        self.result_label.config(
            text=f"Risk Score: {score}   |   Level: {level}"
        )

        self.reasons_list.delete(0, tk.END)

        if reasons:
            for reason in reasons:
                self.reasons_list.insert(tk.END, "• " + reason)
        else:
            self.reasons_list.insert(
                tk.END,
                "✓ No suspicious signs detected."
            )

    def clear(self):
        self.url_entry.delete(0, tk.END)
        self.result_label.config(text="Risk Score: -   |   Level: -")

        for item in self.tree.get_children():
            self.tree.delete(item)

        self.reasons_list.delete(0, tk.END)
        self.last_result = None

    def export_txt(self):
        if not self.last_result:
            messagebox.showwarning("Warning", "Check a URL first.")
            return

        url, result, score, level, reasons = self.last_result

        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt")]
        )

        if not file_path:
            return

        with open(file_path, "w", encoding="utf-8") as file:
            file.write("Phishing Detection & URL Safety Checker\n\n")
            file.write(f"URL: {url}\n")
            file.write(f"Risk Score: {score}\n")
            file.write(f"Risk Level: {level}\n\n")
            file.write("Analysis:\n")

            for feature, detected in result.items():
                file.write(f"{feature}: {detected}\n")

            file.write("\nReasons:\n")

            for reason in reasons:
                file.write(f"- {reason}\n")

        messagebox.showinfo("Success", "TXT report exported successfully.")

    def export_csv(self):
        if not self.last_result:
            messagebox.showwarning("Warning", "Check a URL first.")
            return

        url, result, score, level, reasons = self.last_result

        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv")]
        )

        if not file_path:
            return

        with open(file_path, "w", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)

            writer.writerow(["URL", url])
            writer.writerow(["Risk Score", score])
            writer.writerow(["Risk Level", level])
            writer.writerow([])
            writer.writerow(["Feature", "Detected"])

            for feature, detected in result.items():
                writer.writerow([feature, detected])

            writer.writerow([])
            writer.writerow(["Reasons"])

            for reason in reasons:
                writer.writerow([reason])

        messagebox.showinfo("Success", "CSV report exported successfully.")


if __name__ == "__main__":
    root = tk.Tk()
    app = PhishingCheckerApp(root)
    root.mainloop()
