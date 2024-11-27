const express = require("express");
const multer = require("multer");
const fs = require("fs");
const PDFDocument = require("pdfkit");
const path = require("path");
const { ChartJSNodeCanvas } = require("chartjs-node-canvas");

const app = express();
const PORT = 5000;

// Setup storage for multer
const upload = multer({ dest: "uploads/" });

// Initialize chart canvas
const width = 600; // Width of the chart
const height = 400; // Height of the chart
const chartJSNodeCanvas = new ChartJSNodeCanvas({ width, height });

// Function to extract vulnerabilities from the text file
function extractVulnerabilities(filePath) {
  const content = fs.readFileSync(filePath, "utf8");
  const urlRegex = /Vulnerabilities found on (https?:\/\/[^\s]+):/g;
  const vulnerabilityRegex = /-\s(.+?):/g;

  let match;
  const vulnerabilities = {};

  // Find all URLs and their associated vulnerabilities
  while ((match = urlRegex.exec(content)) !== null) {
    const url = match[1];
    const vulnerabilitiesForUrl = [];

    let startIndex = match.index;
    let endIndex = content.indexOf("Vulnerabilities found on", startIndex + 1);
    if (endIndex === -1) endIndex = content.length;

    const urlBlock = content.slice(startIndex, endIndex);

    let vulnMatch;
    while ((vulnMatch = vulnerabilityRegex.exec(urlBlock)) !== null) {
      vulnerabilitiesForUrl.push(vulnMatch[1].trim());
    }

    vulnerabilities[url] = vulnerabilitiesForUrl;
  }

  return vulnerabilities;
}

// Function to load vulnerability categories
function loadCategories(categoryFilePath) {
  const categories = {
    Critical: [],
    High: [],
    Medium: [],
    Low: [],
  };

  const content = fs.readFileSync(categoryFilePath, "utf8");
  const lines = content.split("\n");

  let currentCategory = null;
  lines.forEach((line) => {
    line = line.trim();
    if (line.startsWith("Critical")) {
      currentCategory = "Critical";
    } else if (line.startsWith("High")) {
      currentCategory = "High";
    } else if (line.startsWith("Medium")) {
      currentCategory = "Medium";
    } else if (line.startsWith("Low")) {
      currentCategory = "Low";
    } else if (currentCategory && line.match(/^\d+\.\s/)) {
      categories[currentCategory].push(line.replace(/^\d+\.\s/, "").trim());
    }
  });

  return categories;
}

// Function to categorize vulnerabilities
function categorizeVulnerabilities(vulnerabilities, categories) {
  const categorized = {
    Critical: [],
    High: [],
    Medium: [],
    Low: [],
  };

  vulnerabilities.forEach((vulnerability) => {
    for (const [category, items] of Object.entries(categories)) {
      if (items.includes(vulnerability)) {
        categorized[category].push(vulnerability);
        break;
      }
    }
  });

  return categorized;
}

// Function to create a chart
async function createChart(data) {
  const configuration = {
    type: "bar",
    data: {
      labels: Object.keys(data),
      datasets: [
        {
          label: "Vulnerabilities Count",
          data: Object.values(data),
          backgroundColor: ["#FF6384", "#36A2EB", "#FFCE56", "#4CAF50"],
        },
      ],
    },
    options: {
      responsive: true,
      plugins: {
        legend: { display: true, position: "top" },
      },
    },
  };
  return chartJSNodeCanvas.renderToBuffer(configuration);
}

// Function to draw the Risk Summary table
function drawRiskSummaryTable(doc, riskSummary) {
    doc.moveDown(2);
    doc.fontSize(14).fillColor('#004d99').text('Risk Summary', { underline: true });
    doc.moveDown(0.5);

    // Table header
    const tableTop = doc.y;
    const tableLeft = 50;
    const columnWidths = [200, 200];

    doc.fontSize(12).fillColor('#000');
    doc.text('Risk Level', tableLeft, tableTop, { width: columnWidths[0], align: 'left' });
    doc.text('Count', tableLeft + columnWidths[0], tableTop, { width: columnWidths[1], align: 'left' });

    doc.moveDown(0.3);
    doc.rect(tableLeft, tableTop - 5, columnWidths[0] + columnWidths[1], 1).fill('#000000'); // Header underline

    // Table rows
    let yPosition = tableTop + 20;
    for (const [riskLevel, count] of Object.entries(riskSummary)) {
        doc.text(riskLevel, tableLeft, yPosition, { width: columnWidths[0], align: 'left' });
        doc.text(count.toString(), tableLeft + columnWidths[0], yPosition, { width: columnWidths[1], align: 'left' });
        yPosition += 20;
    }
}


// Route to upload the text file and generate a PDF
app.post("/generate-pdf", upload.single("file"), async (req, res) => {
  const filePath = req.file.path; // Path to uploaded file
  const fileName = req.file.originalname.replace(".txt", ".pdf");
  const pdfPath = path.join(__dirname, "reports", fileName);

  const categoryFilePath = path.join(__dirname, "category.txt");

  // Ensure the reports directory exists
  if (!fs.existsSync("reports")) {
    fs.mkdirSync("reports");
  }

  // Read the uploaded text file
  fs.readFile(filePath, "utf8", async (err, data) => {
    if (err) {
      return res.status(500).json({ error: "Error reading the file" });
    }

    // Extract vulnerabilities
    const vulnerabilities = extractVulnerabilities(filePath);

    // Load categories
    const categories = loadCategories(categoryFilePath);

    // Categorize vulnerabilities for all URLs
    const overallCategorized = { Critical: 0, High: 0, Medium: 0, Low: 0 };
    for (const vulnList of Object.values(vulnerabilities)) {
      const categorized = categorizeVulnerabilities(vulnList, categories);
      for (const [category, items] of Object.entries(categorized)) {
        overallCategorized[category] += items.length;
      }
    }

    // Generate the chart
    const chartImage = await createChart(overallCategorized);

    // Generate the PDF
    const doc = new PDFDocument({ margin: 50 });
    const writeStream = fs.createWriteStream(pdfPath);
    doc.pipe(writeStream);

    // Add company name and title
    doc.fontSize(14).fillColor("#004d99").text("Aegis", { align: "left" });
    doc.moveDown();
    doc
      .fontSize(20)
      .fillColor("#333333")
      .text("Website Vulnerability Scanner Report", { align: "center" });
    doc.moveDown(0.5);
    const currentDate = new Date().toLocaleString();
    doc
      .fontSize(12)
      .fillColor("#666666")
      .text(`Report created on: ${currentDate}`, { align: "center" });
    doc.moveDown(2);
    // Draw a light blue box
    const boxStartY = doc.y; // Record Y position to draw the box
    doc.rect(50, boxStartY, 500, 400).fill("#E0F7FA").stroke();

    // Write the title inside the box
    doc
      .fillColor("black")
      .fontSize(14)
      .text("Vulnerabilities based on testing Types", 60, boxStartY + 10);

    // List of testing types
    const testingTypes = [
      "Website Fingerprinting",
      "Version-Based Vulnerability Detection",
      "Common Configuration Issues",
      "SQL Injection",
      "Cross-Site Scripting (XSS)",
      "Local/Remote File Inclusion",
      "Remote Command Execution",
      "Discovery of Sensitive Files",
      "Authentication & Authorization Issues",
      "API & Input Handling Issues",
      "API-Specific Issues",
      "Injection & Code Execution Vulnerabilities",
      "Web & API Vulnerabilities",
      "Configuration & Deployment Issues",
      "Web Security Vulnerabilities",
      "Cryptographic & Storage Vulnerabilities",
      "Business Logic Vulnerabilities",
      "Network & Protocol Vulnerabilities",
    ];

    // Add the list inside the box
    doc.fontSize(12);
    testingTypes.forEach((type, index) => {
      doc.text(`${index + 1}. ${type}`, { indent: 20 });
    });

    doc.moveDown(4);

    // Add the chart with proper spacing
    doc.image(chartImage, { align: "center", width: 200,height:100 });
    doc.moveDown(12); // Adjust spacing below the chart
// Add the Risk Summary table
drawRiskSummaryTable(doc, overallCategorized);

    // Add categorized vulnerabilities per URL
    for (const [url, vulnList] of Object.entries(vulnerabilities)) {
      doc
        .fontSize(14)
        .fillColor("#004d99")
        .text(`Vulnerabilities found on: ${url}`);
      doc.moveDown(0.5);

      const categorized = categorizeVulnerabilities(vulnList, categories);
      for (const [category, items] of Object.entries(categorized)) {
        if (items.length > 0) {
          doc
            .fontSize(12)
            .fillColor("#004d99")
            .text(`${category} Vulnerabilities:`);
          items.forEach((vuln) => {
            doc
              .fontSize(12)
              .fillColor("#333333")
              .text(`- ${vuln}`, { indent: 20 });
          });
          doc.moveDown(0.5);
        }
      }
      doc.moveDown(1);
    }

    // Add footer with page numbers
    const range = doc.bufferedPageRange();
    for (let i = range.start; i < range.start + range.count; i++) {
      doc.switchToPage(i);
      doc
        .fontSize(10)
        .fillColor("#666666")
        .text(`Page ${i + 1} of ${range.count}`, 50, 750, { align: "center" });
    }

    doc.end();

    writeStream.on("finish", () => {
      res.download(pdfPath, (downloadErr) => {
        if (downloadErr) {
          return res.status(500).json({ error: "Error downloading the PDF" });
        }
        fs.unlinkSync(filePath);
        fs.unlinkSync(pdfPath);
      });
    });
  });
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
