# Power Security Lib

**Power Security Lib** is a Python library designed to assess the security of power infrastructure for any geographic location. It provides functionality to retrieve infrastructure data, identify critical assets, perform detailed vulnerability assessments, and generate comprehensive security recommendations with cost estimates. The library also offers visualization and reporting tools to help users quickly understand the security posture of a given area.

## Features

- **Data Retrieval:**  
  Retrieve power infrastructure data from OpenStreetMap (OSM) using OSMnx, with support for both live and mock data.

- **Critical Asset Identification:**  
  Automatically identify key assets such as substations, transformers, power lines, poles, and towers.

- **Vulnerability Assessment:**  
  Evaluate risks based on factors such as asset type, voltage, age, proximity to roads/buildings, and physical security measures.

- **Security Strategy Development:**  
  Generate tailored security recommendations with detailed cost ranges, implementation times, and effectiveness ratings.

- **Visualization & Reporting:**  
  Visualize the assessed infrastructure on a map and generate detailed reports in text, JSON, HTML, or Markdown formats.

## Installation

Power Security Lib requires Python 3.7 or higher. You can install the library and its dependencies using `pip`:

```bash
pip install .
```
Alternatively, if you have a requirements.txt file listing the dependencies, run:

```
pip install -r requirements.txt
```
# **Dependencies**
OSMnx
GeoPandas
Shapely
Matplotlib
Pandas
Usage
You can use Power Security Lib in two ways: a one-line full assessment or step-by-step for more control.

One-Line Assessment
python
Copy
from power_security_lib import PowerInfrastructureAnalyzer, run_full_assessment

# **Quick assessment with all steps**
```
analyzer = run_full_assessment(
    location_name="Stanford University, California, USA",
    buffer_distance=1.5,
    save_visualization="output/stanford_map.png",
    save_report="output/stanford_report.html",
    report_format="html"
)
#**Step-by-Step Usage**
```
from power_security_lib import PowerInfrastructureAnalyzer

analyzer = PowerInfrastructureAnalyzer(
    place_name="MIT, Cambridge, Massachusetts",
    buffer_distance=2.0
)
```
# Run individual steps for finer control
analyzer.retrieve_infrastructure_data()
analyzer.identify_critical_assets()
analyzer.assess_vulnerabilities()
analyzer.develop_security_strategy()
analyzer.visualize_infrastructure(save_path="output/mit_map.png")
report = analyzer.generate_report(output_format="markdown", save_path="output/mit_report.md")
```


#**Contributing**
Contributions are welcome! If you'd like to contribute to Power Security Lib, please fork the repository and submit a pull request. For more details on packaging and publishing Python projects, please see these reputable sources:

#**Packaging Python Projects**
Real Python: Publishing a Python Package

#**License**
This project is licensed under the terms of the MIT License.

#**Contact**
For questions, feedback, or further information, please open an issue on the repository or contact the project maintainer.

---

This **README.md** file provides a comprehensive overview of your library, explains installation and usage, describes the project structure, and includes links to reputable sources for further guidance on packaging and publishing Python projects.
