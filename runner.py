from power_security_lib.analyzer import PowerInfrastructureAnalyzer
import matplotlib.pyplot as plt

def run_full_assessment(location_name, buffer_distance=0.5, use_mock_data=False, 
                        save_visualization=None, save_report=None, report_format='text'):
    """
    Run a complete infrastructure security assessment for a location.
    
    Args:
        location_name (str): Name of the location to analyze.
        buffer_distance (float): Distance in kilometers to expand the search area.
        use_mock_data (bool): Whether to use mock data instead of live OSM data.
        save_visualization (str): File path to save the visualization (e.g., "output/map.png").
        save_report (str): File path to save the generated report.
        report_format (str): Format of the report ('text', 'json', 'html', 'markdown').
        
    Returns:
        PowerInfrastructureAnalyzer: The analyzer instance with complete assessment results.
    """
    # Initialize the analyzer with the provided location and parameters.
    analyzer = PowerInfrastructureAnalyzer(
        place_name=location_name,
        buffer_distance=buffer_distance,
        use_mock_data=use_mock_data
    )
    
    print(f"Starting analysis for: {location_name}")
    print(f"Buffer distance: {buffer_distance} km")
    
    # Step 1: Retrieve power infrastructure data.
    print("\nStep 1: Retrieving infrastructure data...")
    data_retrieved = analyzer.retrieve_infrastructure_data()
    if not data_retrieved and not use_mock_data:
        print("Error: Failed to retrieve live data. Switching to mock data...")
        analyzer.use_mock_data = True
        analyzer.retrieve_infrastructure_data()
    
    # Step 2: Identify critical assets.
    print("\nStep 2: Identifying critical assets...")
    analyzer.identify_critical_assets()
    total_assets = sum(len(assets) for assets in analyzer.critical_assets.values())
    print(f"Total critical assets identified: {total_assets}")
    
    # Step 3: Perform vulnerability assessment.
    print("\nStep 3: Performing vulnerability assessment...")
    analyzer.assess_vulnerabilities()
    
    # Step 4: Develop a security strategy.
    print("\nStep 4: Developing security strategy...")
    analyzer.develop_security_strategy()
    
    # Step 5: Visualize the power infrastructure.
    print("\nStep 5: Generating visualization...")
    try:
        analyzer.visualize_infrastructure(save_path=save_visualization)
        if save_visualization:
            print(f"Visualization saved to: {save_visualization}")
        else:
            plt.show()
    except Exception as e:
        print(f"Error generating visualization: {e}")
    
    # Step 6: Generate the vulnerability assessment report.
    print("\nStep 6: Generating vulnerability assessment report...")
    report = analyzer.generate_report(output_format=report_format, save_path=save_report)
    if save_report:
        print(f"Report saved to: {save_report}")
    else:
        print("\n" + "="*40 + " REPORT " + "="*40)
        print(report)
        print("="*89)
    
    return analyzer

if __name__ == "__main__":
    # For testing or quick demonstrations, you can uncomment the following example:
    #
    # analyzer = run_full_assessment(
    #     location_name="Stanford University, California, USA",
    #     buffer_distance=1.5,
    #     save_visualization="output/stanford_map.png",
    #     save_report="output/stanford_report.html",
    #     report_format="html"
    # )
    #
    # Alternatively, you can run a step-by-step assessment using the PowerInfrastructureAnalyzer class.
    pass
