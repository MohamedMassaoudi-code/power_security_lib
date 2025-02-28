import osmnx as ox
import geopandas as gpd
import matplotlib.pyplot as plt
from shapely.geometry import Point, LineString, Polygon
import pandas as pd
from typing import Dict, List, Tuple, Any, Optional, Union
from collections import Counter
import os


class PowerInfrastructureAnalyzer:
    """
    A class for analyzing power infrastructure security at any geographic location.
    """

    def __init__(self, 
                 place_name: str = None, 
                 buffer_distance: float = 0.5, 
                 coords: Tuple[float, float] = None,
                 polygon = None,
                 use_mock_data: bool = False):
        """
        Initialize the PowerInfrastructureAnalyzer.
        
        Args:
            place_name: Name of the location to analyze (e.g., "University of St. Thomas, Houston, Texas, USA")
            buffer_distance: Distance in kilometers to expand the search area (default: 0.5 km)
            coords: Optional tuple of (longitude, latitude) if no place_name is provided
            polygon: Optional polygon geometry to define the area directly
            use_mock_data: Whether to use mock data for demonstration (default: False)
        """
        self.place_name = place_name
        self.buffer_distance = buffer_distance
        self.coords = coords
        self.provided_polygon = polygon
        self.use_mock_data = use_mock_data
        
        # Will be populated after data retrieval
        self.gdf_power = None
        self.roads_gdf = None
        self.buildings_gdf = None
        self.original_polygon = None
        self.buffered_polygon = None
        self.critical_assets = None
        self.threat_assessment = None
        self.defense_strategy = None
        
        # Defense measures dictionary - will be initialized in _init_defense_measures
        self.defense_measures = {}
        self._init_defense_measures()
    
    def _init_defense_measures(self):
        """Initialize the defense measures cost dictionary."""
        self.defense_measures = {
            # Very high risk measures (risk >= 8)
            "Install military-grade perimeter security with 24/7 monitoring": {
                "cost_range": "$150,000 - $300,000",
                "implementation_time": "6-12 months",
                "effectiveness": "Very High",
                "description": "Comprehensive perimeter security system with advanced sensors, thermal cameras, and 24/7 monitoring"
            },
            "Implement biometric access control systems": {
                "cost_range": "$50,000 - $100,000",
                "implementation_time": "3-6 months",
                "effectiveness": "High",
                "description": "Multi-factor authentication including fingerprint, retina scan, or facial recognition"
            },
            "Deploy advanced ICS/SCADA security monitoring and anomaly detection": {
                "cost_range": "$100,000 - $250,000",
                "implementation_time": "4-8 months",
                "effectiveness": "Very High",
                "description": "AI-powered monitoring system that detects and alerts on unusual behavior in industrial control systems"
            },
            "Implement air-gapped backup systems": {
                "cost_range": "$75,000 - $150,000",
                "implementation_time": "3-6 months",
                "effectiveness": "High",
                "description": "Isolated backup systems that are not connected to external networks"
            },
            "Establish a Security Operations Center (SOC) with 24/7 monitoring": {
                "cost_range": "$200,000 - $500,000 annually",
                "implementation_time": "6-12 months",
                "effectiveness": "Very High",
                "description": "Dedicated team for continuous monitoring and incident response"
            },
            "Conduct regular red team exercises and penetration testing": {
                "cost_range": "$30,000 - $80,000 annually",
                "implementation_time": "Ongoing",
                "effectiveness": "High",
                "description": "Simulated attacks to identify and address vulnerabilities"
            },
            "Deploy physical tamper detection sensors on critical equipment": {
                "cost_range": "$20,000 - $50,000",
                "implementation_time": "1-3 months",
                "effectiveness": "Medium-High",
                "description": "Sensors that detect and alert on physical tampering attempts"
            },
            
            # High risk measures (risk >= 7)
            "Install advanced perimeter fencing & surveillance": {
                "cost_range": "$75,000 - $150,000",
                "implementation_time": "3-6 months",
                "effectiveness": "Medium-High",
                "description": "Enhanced physical barriers with camera surveillance"
            },
            "Implement strict access control (multi-factor authentication)": {
                "cost_range": "$25,000 - $60,000",
                "implementation_time": "2-4 months",
                "effectiveness": "High",
                "description": "Systems requiring multiple forms of verification for access"
            },
            "Deploy ICS-aware intrusion detection systems": {
                "cost_range": "$50,000 - $120,000",
                "implementation_time": "3-6 months",
                "effectiveness": "High",
                "description": "Specialized security monitoring for industrial control systems"
            },
            "Segment networks (SCADA vs. corporate) with VLANs/firewalls": {
                "cost_range": "$30,000 - $80,000",
                "implementation_time": "2-5 months",
                "effectiveness": "High",
                "description": "Network isolation to prevent lateral movement"
            },
            "Regular patch management & vulnerability scanning": {
                "cost_range": "$15,000 - $40,000 annually",
                "implementation_time": "Ongoing",
                "effectiveness": "Medium-High",
                "description": "Systematic updating of systems and scanning for vulnerabilities"
            },
            "Implement encrypted communications for control systems": {
                "cost_range": "$20,000 - $60,000",
                "implementation_time": "2-4 months",
                "effectiveness": "Medium-High",
                "description": "Secure, encrypted data transmission for operational technology"
            },
            
            # Medium risk measures (risk >= 5)
            "Upgrade perimeter security (fencing, cameras)": {
                "cost_range": "$30,000 - $80,000",
                "implementation_time": "2-4 months",
                "effectiveness": "Medium",
                "description": "Basic physical security enhancements"
            },
            "Enable role-based access control for ICS systems": {
                "cost_range": "$15,000 - $40,000",
                "implementation_time": "1-3 months",
                "effectiveness": "Medium",
                "description": "Limited access based on user roles and responsibilities"
            },
            "Encrypt data transmissions (VPN/TLS)": {
                "cost_range": "$10,000 - $30,000",
                "implementation_time": "1-2 months",
                "effectiveness": "Medium",
                "description": "Basic encryption for data in transit"
            },
            "Deploy basic intrusion detection systems": {
                "cost_range": "$15,000 - $45,000",
                "implementation_time": "1-3 months",
                "effectiveness": "Medium",
                "description": "Standard security monitoring for unauthorized access"
            },
            "Implement regular backup procedures": {
                "cost_range": "$8,000 - $25,000",
                "implementation_time": "1-2 months",
                "effectiveness": "Medium",
                "description": "Systematic data backup to enable recovery"
            },
            
            # Low risk measures (risk < 5)
            "Maintain basic surveillance and access control": {
                "cost_range": "$10,000 - $30,000",
                "implementation_time": "1-2 months",
                "effectiveness": "Low-Medium",
                "description": "Minimal physical security controls"
            },
            "Conduct periodic cybersecurity assessments": {
                "cost_range": "$5,000 - $15,000 annually",
                "implementation_time": "Recurring",
                "effectiveness": "Low-Medium",
                "description": "Occasional evaluation of security posture"
            },
            "Develop basic security policies and procedures": {
                "cost_range": "$3,000 - $10,000",
                "implementation_time": "1-2 months",
                "effectiveness": "Low",
                "description": "Documentation of security expectations and processes"
            },
            
            # Common measures for all risk levels
            "Implement security awareness training for staff": {
                "cost_range": "$5,000 - $15,000 annually",
                "implementation_time": "Ongoing",
                "effectiveness": "Medium",
                "description": "Regular training to promote security-conscious behavior"
            },
            "Establish incident response procedures": {
                "cost_range": "$8,000 - $20,000",
                "implementation_time": "1-3 months",
                "effectiveness": "Medium-High",
                "description": "Documented processes for handling security incidents"
            },
            "Conduct regular security audits": {
                "cost_range": "$10,000 - $30,000 annually",
                "implementation_time": "Recurring",
                "effectiveness": "Medium",
                "description": "Systematic review of security controls and compliance"
            }
        }
    
    def retrieve_infrastructure_data(self) -> bool:
        """
        Retrieve power infrastructure data for the specified location.
        
        Returns:
            bool: True if data retrieval was successful, False otherwise.
        """
        if self.use_mock_data:
            self._create_mock_data()
            return True
            
        try:
            if self.provided_polygon:
                self.original_polygon = self.provided_polygon
            elif self.place_name:
                print(f"Geocoding {self.place_name} to obtain its boundary...")
                gdf_place = ox.geocode_to_gdf(self.place_name)
                if gdf_place.empty:
                    raise ValueError("No geographic boundary found for the provided place.")
                self.original_polygon = gdf_place.geometry.iloc[0]
            elif self.coords:
                # Create a small circular buffer around the point
                point = Point(self.coords)
                self.original_polygon = point.buffer(0.001)  # Small initial buffer
            else:
                raise ValueError("Either place_name, coords, or polygon must be provided.")
            
            # Add buffer to expand search area
            # Convert to a projected CRS for accurate distance measurement in meters
            gdf_orig = gpd.GeoDataFrame(geometry=[self.original_polygon], crs="EPSG:4326")
            gdf_orig_proj = gdf_orig.to_crs(epsg=3857)  # Web Mercator projection
            buffer_meters = self.buffer_distance * 1000  # Convert km to meters
            buffered_polygon_proj = gdf_orig_proj.geometry.iloc[0].buffer(buffer_meters)
            
            # Convert back to WGS84 (EPSG:4326) for OSM
            gdf_buffer = gpd.GeoDataFrame(geometry=[buffered_polygon_proj], crs=gdf_orig_proj.crs)
            gdf_buffer = gdf_buffer.to_crs(epsg=4326)
            self.buffered_polygon = gdf_buffer.geometry.iloc[0]
            
            print(f"Expanded search area with a {self.buffer_distance} km buffer...")
            
            tags = {"power": True}  # Query any feature that has the key 'power'
            print("Querying power infrastructure features within the expanded boundary...")
            self.gdf_power = self._query_osm_features(self.buffered_polygon, tags)
            
            # Also get roads network for vulnerability assessment
            try:
                print("Retrieving road network for vulnerability assessment...")
                self.roads_gdf = self._query_osm_features(self.buffered_polygon, {"highway": True})
            except Exception as e:
                print(f"Warning: Could not retrieve road network: {e}")
                self.roads_gdf = gpd.GeoDataFrame()
            
            # Get buildings for vulnerability assessment
            try:
                print("Retrieving buildings for vulnerability assessment...")
                self.buildings_gdf = self._query_osm_features(self.buffered_polygon, {"building": True})
            except Exception as e:
                print(f"Warning: Could not retrieve buildings: {e}")
                self.buildings_gdf = gpd.GeoDataFrame()
                
            if len(self.gdf_power) == 0:
                print("No power infrastructure found. Consider using mock data or increasing buffer distance.")
                return False
                
            return True
                
        except Exception as e:
            print(f"Error retrieving data: {e}")
            return False
    
    def _query_osm_features(self, polygon, tags):
        """
        Query OSM features with given tags within a polygon.
        Handles different OSMnx versions.
        
        Args:
            polygon: The polygon to query within
            tags: Dictionary of OSM tags to query for
            
        Returns:
            GeoDataFrame with the requested features
        """
        try:
            # Try the current OSMnx API (as of recent versions)
            return ox.features_from_polygon(polygon, tags=tags)
        except AttributeError:
            try:
                # For older OSMnx versions, the function might be in a different location
                return ox.geometries.geometries_from_polygon(polygon, tags=tags)
            except (AttributeError, ImportError):
                try:
                    # Another possible location in newer versions
                    from osmnx import geometries
                    return geometries.geometries_from_polygon(polygon, tags=tags)
                except (AttributeError, ImportError):
                    raise ImportError("Could not find the correct function to query OSM features. "
                                    "Please check your OSMnx version and update the code accordingly.")
    
    def _create_mock_data(self):
        """Create mock data for demonstration purposes."""
        print("Creating mock data for demonstration purposes...")
        
        # Use provided coords or default to Houston, TX
        if self.coords:
            center_point = Point(self.coords)
        else:
            # Default to University of St. Thomas, Houston coordinates
            center_point = Point(-95.3910, 29.7380)
        
        # Create a mock GeoDataFrame with sample power infrastructure
        mock_data = {
            'geometry': [
                center_point.buffer(0.001),  # A substation
                LineString([(center_point.x - 0.01, center_point.y), 
                           (center_point.x + 0.01, center_point.y)]),  # A power line
                Point(center_point.x + 0.002, center_point.y + 0.003),  # A transformer
                Point(center_point.x - 0.005, center_point.y - 0.004),  # Another transformer
                LineString([(center_point.x, center_point.y - 0.01), 
                           (center_point.x, center_point.y + 0.01)]),  # Another power line
            ],
            'power': ['substation', 'line', 'transformer', 'transformer', 'line'],
            'tags': [
                {'power': 'substation', 'voltage': '138kV', 'start_date': '1985'},
                {'power': 'line', 'voltage': '69kV'},
                {'power': 'transformer', 'voltage': '13.8kV', 'year': '2010'},
                {'power': 'transformer', 'voltage': '34.5kV', 'start_date': '1995'},
                {'power': 'line', 'voltage': '138kV', 'year': '2015'}
            ]
        }
        self.gdf_power = gpd.GeoDataFrame(mock_data, crs="EPSG:4326")
        
        # Create mock road data
        roads_data = {
            'geometry': [
                LineString([(center_point.x - 0.02, center_point.y - 0.02), 
                           (center_point.x + 0.02, center_point.y - 0.02)]),  # Road 1
                LineString([(center_point.x - 0.015, center_point.y - 0.02), 
                           (center_point.x - 0.015, center_point.y + 0.02)]),  # Road 2
            ],
            'highway': ['residential', 'secondary'],
            'name': ['Main St', 'College Ave']
        }
        self.roads_gdf = gpd.GeoDataFrame(roads_data, crs="EPSG:4326")
        
        # Create mock building data
        buildings_data = {
            'geometry': [
                Polygon([
                    (center_point.x - 0.005, center_point.y - 0.005),
                    (center_point.x + 0.005, center_point.y - 0.005),
                    (center_point.x + 0.005, center_point.y + 0.005),
                    (center_point.x - 0.005, center_point.y + 0.005),
                    (center_point.x - 0.005, center_point.y - 0.005)
                ]),  # Main building
                Polygon([
                    (center_point.x - 0.01, center_point.y - 0.01),
                    (center_point.x - 0.008, center_point.y - 0.01),
                    (center_point.x - 0.008, center_point.y - 0.008),
                    (center_point.x - 0.01, center_point.y - 0.008),
                    (center_point.x - 0.01, center_point.y - 0.01)
                ]),  # Small building
            ],
            'building': ['university', 'residential'],
            'name': ['Admin Building', 'Student Housing']
        }
        self.buildings_gdf = gpd.GeoDataFrame(buildings_data, crs="EPSG:4326")
        
        # Create mock boundary polygons
        self.original_polygon = center_point.buffer(0.01)
        self.buffered_polygon = center_point.buffer(0.02)
    
    def identify_critical_assets(self) -> Dict[str, gpd.GeoDataFrame]:
        """
        Identify critical power assets from the retrieved data.
        
        Returns:
            Dictionary with lists of critical assets by type.
        """
        if self.gdf_power is None:
            print("Error: No power infrastructure data available. Run retrieve_infrastructure_data() first.")
            return {}
            
        # Handle case where 'power' column might not exist
        if 'power' not in self.gdf_power.columns:
            print("Warning: 'power' column not found in data. Using tags dictionary instead.")
            # Try to extract power information from the tags column if it exists
            if 'tags' in self.gdf_power.columns:
                self.gdf_power['power'] = self.gdf_power['tags'].apply(lambda x: x.get('power') if isinstance(x, dict) else None)
            else:
                print("Error: Could not find power type information in the data.")
                return {"substations": gpd.GeoDataFrame(), "lines": gpd.GeoDataFrame()}

        # Filter for substations
        substations = self.gdf_power[self.gdf_power["power"] == "substation"]

        # Filter for lines (transmission or distribution)
        # OSM might store them as 'power=line' or 'power=minor_line'
        lines = self.gdf_power[(self.gdf_power["power"] == "line") | (self.gdf_power["power"] == "minor_line")]

        # Add any transformers as they're also critical
        transformers = self.gdf_power[self.gdf_power["power"] == "transformer"]
        
        # Additional critical assets
        poles = self.gdf_power[self.gdf_power["power"] == "pole"]
        towers = self.gdf_power[self.gdf_power["power"] == "tower"]
        
        critical_assets = {
            "substations": substations,
            "lines": lines,
            "transformers": transformers,
            "poles": poles,
            "towers": towers
        }
        
        # Print summary of assets found
        for asset_type, assets in critical_assets.items():
            print(f"Found {len(assets)} {asset_type}")
            
        # Remove empty asset types
        self.critical_assets = {k: v for k, v in critical_assets.items() if len(v) > 0}
        return self.critical_assets
    
    def assess_vulnerabilities(self, threat_type: str = "cyber-physical intrusion") -> Dict:
        """
        Perform a comprehensive vulnerability assessment.
        
        Args:
            threat_type: Type of threat to assess (default: "cyber-physical intrusion")
            
        Returns:
            Dictionary with vulnerability assessment results
        """
        if self.critical_assets is None:
            print("Error: No critical assets identified. Run identify_critical_assets() first.")
            return {}
            
        assessment_results = {}
        vulnerability_factors = {}

        # Check if we have road and building data for proximity analysis
        has_roads = self.roads_gdf is not None and not self.roads_gdf.empty
        has_buildings = self.buildings_gdf is not None and not self.buildings_gdf.empty

        print(f"Performing vulnerability assessment for threat: {threat_type}")
        
        # More sophisticated scoring based on asset characteristics and vulnerabilities
        for asset_type, gdf in self.critical_assets.items():
            risk_scores = []
            asset_vulnerabilities = {}
            
            if len(gdf) == 0:
                print(f"No {asset_type} found to assess.")
                continue
                
            for idx, row in gdf.iterrows():
                # Initialize vulnerability factors dictionary for this asset
                vulnerability_factors[idx] = {}
                
                # 1. BASE RISK SCORE - Type-based initial assessment
                if asset_type == "substations":
                    risk_score = 8  # Substations are high-value targets
                    vulnerability_factors[idx]["base_type"] = "High value target (substation)"
                elif asset_type == "transformers":
                    risk_score = 7  # Transformers are also critical
                    vulnerability_factors[idx]["base_type"] = "Critical equipment (transformer)"
                elif asset_type == "lines":
                    risk_score = 5  # Lines are less vulnerable to cyber attacks
                    vulnerability_factors[idx]["base_type"] = "Distribution infrastructure (line)"
                elif asset_type in ["poles", "towers"]:
                    risk_score = 4  # Supporting infrastructure
                    vulnerability_factors[idx]["base_type"] = f"Supporting infrastructure ({asset_type})"
                else:
                    risk_score = 4  # Default for other assets
                    vulnerability_factors[idx]["base_type"] = f"Power infrastructure ({asset_type})"
                    
                # 2. VOLTAGE ASSESSMENT - Higher voltage = more critical
                voltage = None
                if 'voltage' in row:
                    voltage = row['voltage']
                elif 'tags' in row and isinstance(row['tags'], dict):
                    voltage = row['tags'].get('voltage')
                    
                if voltage:
                    try:
                        # Convert voltage to numeric if possible
                        voltage_value = pd.to_numeric(voltage.split(';')[0].replace('kV', ''))
                        if voltage_value > 100:  # High voltage
                            risk_score += 2
                            vulnerability_factors[idx]["voltage"] = f"High voltage ({voltage_value}kV)"
                        elif voltage_value > 50:  # Medium voltage
                            risk_score += 1
                            vulnerability_factors[idx]["voltage"] = f"Medium voltage ({voltage_value}kV)"
                        else:
                            vulnerability_factors[idx]["voltage"] = f"Low voltage ({voltage_value}kV)"
                    except (ValueError, AttributeError):
                        vulnerability_factors[idx]["voltage"] = "Unknown voltage"
                else:
                    vulnerability_factors[idx]["voltage"] = "Unknown voltage"
                
                # 3. AGE ASSESSMENT - Older infrastructure is more vulnerable
                age_factor = self._assess_age_factor(row)
                risk_score += age_factor[0]
                vulnerability_factors[idx]["age"] = age_factor[1]
                
                # 4. PROXIMITY ANALYSIS - Closeness to roads and public buildings
                proximity_factors = self._assess_proximity(row, has_roads, has_buildings)
                risk_score += proximity_factors[0]
                vulnerability_factors[idx].update(proximity_factors[1])
                
                # 5. PHYSICAL SECURITY ASSESSMENT - Based on OSM tags
                security_factor = self._assess_security_measures(row)
                risk_score += security_factor[0]
                vulnerability_factors[idx]["physical_security"] = security_factor[1]
                    
                # 6. CONNECTIVITY/CENTRALITY (for lines)
                if asset_type == "lines" and 'geometry' in row:
                    connectivity = self._assess_connectivity(row)
                    risk_score += connectivity[0]
                    vulnerability_factors[idx]["connectivity"] = connectivity[1]
                
                # 7. Cap the risk score at 10
                risk_score = min(round(risk_score, 1), 10)
                
                # Store the calculated risk score and vulnerability factors
                risk_scores.append((idx, risk_score, vulnerability_factors[idx]))
                
            assessment_results[asset_type] = risk_scores

        self.threat_assessment = assessment_results
        return assessment_results
    
    def _assess_age_factor(self, row) -> Tuple[float, str]:
        """Assess the age factor for an asset."""
        age_factor = 0
        age_description = "Unknown age"
        
        timestamp = None
        if 'tags' in row and isinstance(row['tags'], dict):
            # Check for explicit year tags
            for key in ['start_date', 'year', 'construction_date', 'date']:
                if key in row['tags']:
                    try:
                        year = int(row['tags'][key][:4])  # Extract year from date string
                        current_year = 2025  # Current year
                        age = current_year - year
                        
                        if age > 30:  # Very old (30+ years)
                            age_factor = 2
                            age_description = f"Legacy infrastructure (~{age} years old)"
                        elif age > 15:  # Older (15-30 years)
                            age_factor = 1
                            age_description = f"Aging infrastructure (~{age} years old)"
                        else:
                            age_description = f"Modern infrastructure (~{age} years old)"
                        
                        timestamp = True
                        break
                    except (ValueError, TypeError):
                        pass
        
        # If no explicit timestamp, use a heuristic based on OSM ID (lower IDs tend to be older entries)
        if not timestamp and hasattr(row, 'osmid'):
            try:
                # This is just a heuristic - not accurate but gives some variability
                osmid = int(row.osmid)
                if osmid < 1000000:  # Very early OSM entry
                    age_factor = 2
                    age_description = "Likely legacy infrastructure (based on metadata)"
                elif osmid < 5000000:  # Older OSM entry
                    age_factor = 1
                    age_description = "Potentially aging infrastructure (based on metadata)"
            except (ValueError, AttributeError):
                pass
                
        return age_factor, age_description
    
    def _assess_proximity(self, row, has_roads, has_buildings) -> Tuple[float, Dict[str, str]]:
        """Assess proximity to roads and buildings."""
        proximity_factor = 0
        proximity_descriptions = {}
        
        if has_roads and 'geometry' in row:
            try:
                # Calculate distance to nearest road
                asset_geom = row.geometry
                distances = self.roads_gdf.geometry.apply(lambda x: asset_geom.distance(x))
                min_distance = distances.min() if not distances.empty else 999
                
                # Convert to approximate meters (rough conversion from degrees)
                # 1 degree ≈ 111,000 meters at the equator
                min_distance_meters = min_distance * 111000
                
                if min_distance_meters < 50:  # Very close to road
                    proximity_factor += 2
                    proximity_descriptions["road_proximity"] = f"Directly accessible from road (~{min_distance_meters:.1f}m)"
                elif min_distance_meters < 200:  # Reasonably close
                    proximity_factor += 1
                    proximity_descriptions["road_proximity"] = f"Near road access (~{min_distance_meters:.1f}m)"
                else:
                    proximity_descriptions["road_proximity"] = f"Distant from roads (~{min_distance_meters:.1f}m)"
            except Exception as e:
                proximity_descriptions["road_proximity"] = "Could not assess road proximity"
        
        if has_buildings and 'geometry' in row:
            try:
                # Calculate distance to nearest building
                asset_geom = row.geometry
                distances = self.buildings_gdf.geometry.apply(lambda x: asset_geom.distance(x))
                min_distance = distances.min() if not distances.empty else 999
                
                # Convert to approximate meters
                min_distance_meters = min_distance * 111000
                
                if min_distance_meters < 20:  # Very close to building
                    proximity_factor += 1
                    proximity_descriptions["building_proximity"] = f"Directly adjacent to building (~{min_distance_meters:.1f}m)"
                elif min_distance_meters < 100:  # Reasonably close
                    proximity_factor += 0.5
                    proximity_descriptions["building_proximity"] = f"Near building (~{min_distance_meters:.1f}m)"
                else:
                    proximity_descriptions["building_proximity"] = f"Isolated from buildings (~{min_distance_meters:.1f}m)"
            except Exception as e:
                proximity_descriptions["building_proximity"] = "Could not assess building proximity"
                
        return proximity_factor, proximity_descriptions
    
    def _assess_security_measures(self, row) -> Tuple[float, str]:
        """Assess physical security measures based on OSM tags."""
        security_factor = 0
        security_description = "Unknown security measures"
        
        if 'tags' in row and isinstance(row['tags'], dict):
            # Look for security-related tags
            has_fence = any(key in row['tags'] for key in ['fence', 'barrier', 'wall'])
            has_surveillance = any(key in row['tags'] for key in ['surveillance', 'camera', 'cctv'])
            has_access_control = any(key in row['tags'] for key in ['access', 'restricted'])
            
            security_measures = []
            if has_fence:
                security_factor -= 0.5
                security_measures.append("fencing")
            if has_surveillance:
                security_factor -= 0.5
                security_measures.append("surveillance")
            if has_access_control:
                security_factor -= 0.5
                security_measures.append("access control")
                
            if security_measures:
                security_description = f"Has {', '.join(security_measures)}"
            else:
                security_description = "No visible security measures"
                security_factor += 1
                
        return security_factor, security_description
    
    def _assess_connectivity(self, row) -> Tuple[float, str]:
        """Assess connectivity of a line to other infrastructure."""
        connectivity_factor = 0
        connectivity_description = "Could not assess connectivity"
        
        try:
            # Check if this line connects to multiple other features
            line_geom = row.geometry
            connections = 0
            
            # Count connections to substations and transformers
            for connect_type in ["substations", "transformers"]:
                if connect_type in self.critical_assets:
                    for _, connect_row in self.critical_assets[connect_type].iterrows():
                        if connect_row.geometry.distance(line_geom) < 0.001:  # Very close
                            connections += 1
            
            if connections > 1:
                connectivity_factor = 1.5
                connectivity_description = f"Critical connection point ({connections} connections)"
            elif connections == 1:
                connectivity_description = "Single connection"
            else:
                connectivity_description = "Isolated segment"
        except Exception:
            pass
            
        return connectivity_factor, connectivity_description
    
    def develop_security_strategy(self) -> Dict:
        """
        Develop a comprehensive security strategy based on the vulnerability assessment.
        
        Returns:
            Dictionary of recommended measures for each asset type, including cost estimates.
        """
        if self.threat_assessment is None:
            print("Error: No vulnerability assessment available. Run assess_vulnerabilities() first.")
            return {}
            
        strategy = {}
        for asset_type, assessments in self.threat_assessment.items():
            if not assessments:
                continue  # Skip if no assets of this type
                
            recommended_measures = []
            vulnerabilities_summary = {}
            
            # Calculate average risk score
            avg_risk = sum(score for _, score, _ in assessments) / len(assessments) if assessments else 0
            
            # Analyze vulnerability factors across all assets of this type
            all_factors = {}
            for _, _, factors in assessments:
                for factor_type, factor_value in factors.items():
                    if factor_type not in all_factors:
                        all_factors[factor_type] = []
                    all_factors[factor_type].append(factor_value)
            
            # Summarize the most common factors
            for factor_type, values in all_factors.items():
                if values:
                    # Get most frequent value
                    most_common = Counter(values).most_common(1)[0][0]
                    vulnerabilities_summary[factor_type] = most_common
            
            # Common measures for all critical infrastructure
            common_measures = [
                "Implement security awareness training for staff",
                "Establish incident response procedures",
                "Conduct regular security audits"
            ]

            if avg_risk >= 8:  # Very high risk
                recommended_measures.extend([
                    "Install military-grade perimeter security with 24/7 monitoring",
                    "Implement biometric access control systems",
                    "Deploy advanced ICS/SCADA security monitoring and anomaly detection",
                    "Implement air-gapped backup systems",
                    "Establish a Security Operations Center (SOC) with 24/7 monitoring",
                    "Conduct regular red team exercises and penetration testing",
                    "Deploy physical tamper detection sensors on critical equipment"
                ])
            elif avg_risk >= 7:  # High risk
                recommended_measures.extend([
                    "Install advanced perimeter fencing & surveillance",
                    "Implement strict access control (multi-factor authentication)",
                    "Deploy ICS-aware intrusion detection systems",
                    "Segment networks (SCADA vs. corporate) with VLANs/firewalls",
                    "Regular patch management & vulnerability scanning",
                    "Implement encrypted communications for control systems"
                ])
            elif avg_risk >= 5:  # Medium risk
                recommended_measures.extend([
                    "Upgrade perimeter security (fencing, cameras)",
                    "Enable role-based access control for ICS systems",
                    "Encrypt data transmissions (VPN/TLS)",
                    "Deploy basic intrusion detection systems",
                    "Implement regular backup procedures"
                ])
            else:  # Low risk
                recommended_measures.extend([
                    "Maintain basic surveillance and access control",
                    "Conduct periodic cybersecurity assessments",
                    "Develop basic security policies and procedures"
                ])

            # Add common measures to all risk levels
            recommended_measures.extend(common_measures)
            
            # Remove duplicates while preserving order
            recommended_measures = list(dict.fromkeys(recommended_measures))
            
            # Add tailored measures based on specific vulnerabilities
            if vulnerabilities_summary.get('road_proximity', '').startswith('Directly accessible'):
                if "Install advanced perimeter fencing & surveillance" not in recommended_measures:
                    recommended_measures.append("Install advanced perimeter fencing & surveillance")
            
            if vulnerabilities_summary.get('age', '').startswith('Legacy'):
                if "Regular patch management & vulnerability scanning" not in recommended_measures:
                    recommended_measures.append("Regular patch management & vulnerability scanning")
            
            if vulnerabilities_summary.get('physical_security', '') == 'No visible security measures':
                if avg_risk < 7 and "Implement strict access control (multi-factor authentication)" not in recommended_measures:
                    recommended_measures.append("Implement strict access control (multi-factor authentication)")
            
            # Create detailed measure information with costs
            detailed_measures = []
            total_min_cost = 0
            total_max_cost = 0
            
            for measure in recommended_measures:
                measure_details = self.defense_measures.get(measure, {
                    "cost_range": "Varies",
                    "implementation_time": "Unknown",
                    "effectiveness": "Unknown",
                    "description": "Custom measure"
                })
                
                detailed_measures.append({
                    "name": measure,
                    "cost_range": measure_details["cost_range"],
                    "implementation_time": measure_details["implementation_time"],
                    "effectiveness": measure_details["effectiveness"],
                    "description": measure_details["description"]
                })
                
                # Calculate total cost range
                if measure_details["cost_range"] != "Varies":
                    try:
                        # Extract numeric values from cost range
                        cost_str = measure_details["cost_range"].replace("$", "").replace(",", "")
                        min_cost, max_cost = cost_str.split(" - ")
                        if "annually" in min_cost:
                            min_cost = min_cost.replace(" annually", "")
                        if "annually" in max_cost:
                            max_cost = max_cost.replace(" annually", "")
                        
                        total_min_cost += int(min_cost)
                        total_max_cost += int(max_cost)
                    except Exception:
                        pass

            strategy[asset_type] = {
                "average_risk": avg_risk,
                "vulnerabilities": vulnerabilities_summary,
                "detailed_measures": detailed_measures,
                "total_cost_range": f"${total_min_cost:,} - ${total_max_cost:,}",
                "implementation_priority": "Critical" if avg_risk >= 8 else "High" if avg_risk >= 7 else "Medium" if avg_risk >= 5 else "Low"
            }

        self.defense_strategy = strategy
        return strategy
    
    def visualize_infrastructure(self, save_path: str = None) -> Tuple[plt.Figure, plt.Axes]:
        """
        Visualize the critical infrastructure on a map.
        
        Args:
            save_path: Optional path to save the visualization (e.g., "output/map.png")
            
        Returns:
            Tuple of (Figure, Axes) for the visualization
        """
        if self.critical_assets is None:
            print("Error: No critical assets identified. Run identify_critical_assets() first.")
            return None, None
            
        fig, ax = plt.subplots(figsize=(12, 10))
        
        # Define a title based on the location
        title = "Power Infrastructure"
        if self.place_name:
            title += f" near {self.place_name}"
        
        # Get a base map for context
        try:
            # Try to plot the buffered polygon as boundary
            if self.buffered_polygon is not None:
                gpd.GeoDataFrame(geometry=[self.buffered_polygon], crs="EPSG:4326").plot(
                    ax=ax, color='none', edgecolor='black', linewidth=1, alpha=0.5, zorder=1
                )
                
            # Try to plot the original polygon as study area
            if self.original_polygon is not None:
                gpd.GeoDataFrame(geometry=[self.original_polygon], crs="EPSG:4326").plot(
                    ax=ax, color='red', edgecolor='red', linewidth=2, alpha=0.2, zorder=2
                )
                
            # Try to get a street network for context
            if self.place_name:
                try:
                    G = ox.graph_from_place(self.place_name, network_type="drive")
                    ox.plot_graph(G, ax=ax, show=False, close=False, edge_color='gray', 
                                edge_linewidth=0.5, node_size=0, zorder=3)
                except Exception as e:
                    print(f"Could not retrieve street network: {e}")
        except Exception as e:
            print(f"Could not plot boundary: {e}")
        
        # Plot roads and buildings for context if available
        if self.roads_gdf is not None and not self.roads_gdf.empty:
            self.roads_gdf.plot(ax=ax, color='gray', linewidth=0.5, alpha=0.5, zorder=4)
            
        if self.buildings_gdf is not None and not self.buildings_gdf.empty:
            self.buildings_gdf.plot(ax=ax, color='lightgray', alpha=0.3, zorder=5)
        
        # Plot power infrastructure assets
        colors = {
            "substations": "red",
            "transformers": "orange",
            "lines": "blue",
            "poles": "green",
            "towers": "purple"
        }
        
        z_order = 10
        for asset_type, gdf in self.critical_assets.items():
            if len(gdf) > 0:
                gdf.plot(ax=ax, color=colors.get(asset_type, "green"), 
                        label=asset_type.capitalize(), alpha=0.7, zorder=z_order)
                z_order += 1
        
        ax.set_title(title)
        
        # Create custom legend entries
        from matplotlib.lines import Line2D
        legend_elements = [
            Line2D([0], [0], marker='o', color='w', markerfacecolor=colors.get(asset_type, "green"),
                  markersize=10, label=asset_type.capitalize())
            for asset_type in self.critical_assets if asset_type in colors
        ]
        ax.legend(handles=legend_elements, loc='best')
        
        # Save the visualization if requested
        if save_path:
            os.makedirs(os.path.dirname(save_path), exist_ok=True)
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            print(f"Visualization saved to: {save_path}")
        
        return fig, ax
    
    def generate_report(self, output_format='text', save_path=None) -> str:
        """
        Generate a comprehensive vulnerability assessment report.
        
        Args:
            output_format: Format of the report ('text', 'json', 'html', 'markdown')
            save_path: Optional path to save the report
            
        Returns:
            String containing the report in the specified format
        """
        if self.threat_assessment is None or self.defense_strategy is None:
            print("Error: Complete the vulnerability assessment and defense strategy first.")
            return ""
            
        if output_format == 'text':
            report = self._generate_text_report()
        elif output_format == 'json':
            import json
            report_data = {
                "location": self.place_name or "Custom Location",
                "assessment_date": pd.Timestamp.now().strftime("%Y-%m-%d"),
                "assets": {},
                "total_assets": sum(len(assets) for assets in self.critical_assets.values()),
                "overall_risk": self._calculate_overall_risk()
            }
            
            for asset_type, strategy in self.defense_strategy.items():
                report_data["assets"][asset_type] = {
                    "count": len(self.critical_assets[asset_type]),
                    "average_risk": strategy["average_risk"],
                    "priority": strategy["implementation_priority"],
                    "vulnerabilities": strategy["vulnerabilities"],
                    "measures": [m["name"] for m in strategy["detailed_measures"]],
                    "cost_range": strategy["total_cost_range"]
                }
                
            report = json.dumps(report_data, indent=2)
        elif output_format == 'html':
            report = self._generate_html_report()
        elif output_format == 'markdown':
            report = self._generate_markdown_report()
        else:
            print(f"Unsupported format: {output_format}")
            return ""
            
        if save_path:
            os.makedirs(os.path.dirname(save_path), exist_ok=True)
            with open(save_path, 'w') as f:
                f.write(report)
            print(f"Report saved to: {save_path}")
            
        return report
    
    def _calculate_overall_risk(self) -> float:
        """Calculate the overall risk score across all assets."""
        all_scores = []
        for asset_type, assessments in self.threat_assessment.items():
            for _, score, _ in assessments:
                all_scores.append(score)
                
        return sum(all_scores) / len(all_scores) if all_scores else 0
    
    def _generate_text_report(self) -> str:
        """Generate a text-based vulnerability report."""
        lines = []
        lines.append("="*80)
        lines.append(" "*30 + "VULNERABILITY ASSESSMENT REPORT")
        lines.append("="*80)
        
        lines.append(f"\nLocation: {self.place_name or 'Custom Location'}")
        lines.append(f"Assessment Date: {pd.Timestamp.now().strftime('%Y-%m-%d')}")
        lines.append(f"Total Assets Assessed: {sum(len(assets) for assets in self.critical_assets.values())}")
        lines.append(f"Overall Risk Level: {self._calculate_overall_risk():.2f}/10")
        lines.append("\n" + "-"*80)
        
        for asset_type, assessments in self.threat_assessment.items():
            if not assessments:
                continue
                
            lines.append(f"\nASSET TYPE: {asset_type.upper()}")
            lines.append("-"*80)
            
            avg_risk = self.defense_strategy[asset_type]["average_risk"]
            lines.append(f"Average Risk Score: {avg_risk:.2f} - Priority: {self.defense_strategy[asset_type]['implementation_priority']}")
            
            lines.append("\nVulnerability Factors:")
            for factor_type, factor_value in self.defense_strategy[asset_type]["vulnerabilities"].items():
                lines.append(f"  • {factor_type.replace('_', ' ').title()}: {factor_value}")
            
            lines.append("\nDetailed Asset Assessment:")
            for i, (idx, score, factors) in enumerate(assessments):
                lines.append(f"  Asset #{i+1} - Risk Score: {score}")
                for factor_type, factor_value in factors.items():
                    lines.append(f"    - {factor_type.replace('_', ' ').title()}: {factor_value}")
                lines.append("")
            
            lines.append("Recommended Defense Measures:")
            for i, measure in enumerate(self.defense_strategy[asset_type]["detailed_measures"]):
                lines.append(f"  {i+1}. {measure['name']}")
                lines.append(f"     Cost: {measure['cost_range']}")
                lines.append(f"     Implementation Time: {measure['implementation_time']}")
                lines.append(f"     Effectiveness: {measure['effectiveness']}")
                lines.append(f"     Description: {measure['description']}")
                lines.append("")
                
            lines.append(f"Total Estimated Cost Range: {self.defense_strategy[asset_type]['total_cost_range']}")
            lines.append("-"*80)
        
        lines.append("\n" + "="*80)
        lines.append(" "*25 + "END OF VULNERABILITY ASSESSMENT REPORT")
        lines.append("="*80 + "\n")
        
        return "\n".join(lines)
    
    def _generate_html_report(self) -> str:
        """Generate an HTML vulnerability report."""
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Power Infrastructure Vulnerability Assessment</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                h1, h2, h3 {{ color: #333366; }}
                .header {{ text-align: center; background-color: #f0f0f0; padding: 10px; }}
                .section {{ margin: 20px 0; padding: 10px; border: 1px solid #ddd; }}
                .asset-header {{ background-color: #eee; padding: 5px 10px; }}
                .measure {{ margin: 10px 0; padding: 5px; background-color: #f9f9f9; }}
                .high-risk {{ color: #cc0000; }}
                .medium-risk {{ color: #ff6600; }}
                .low-risk {{ color: #339933; }}
                table {{ width: 100%; border-collapse: collapse; }}
                th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }}
                th {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Power Infrastructure Vulnerability Assessment</h1>
                <p>Location: {self.place_name or 'Custom Location'}</p>
                <p>Assessment Date: {pd.Timestamp.now().strftime('%Y-%m-%d')}</p>
                <p>Total Assets: {sum(len(assets) for assets in self.critical_assets.values())}</p>
                <p>Overall Risk Level: <span class="{self._get_risk_class(self._calculate_overall_risk())}">{self._calculate_overall_risk():.2f}/10</span></p>
            </div>
        """
        
        html += """
            <div class="section">
                <h2>Summary of Critical Assets</h2>
                <table>
                    <tr>
                        <th>Asset Type</th>
                        <th>Count</th>
                        <th>Average Risk</th>
                        <th>Priority</th>
                        <th>Estimated Cost Range</th>
                    </tr>
        """
        
        for asset_type, strategy in self.defense_strategy.items():
            html += f"""
                <tr>
                    <td>{asset_type.capitalize()}</td>
                    <td>{len(self.critical_assets[asset_type])}</td>
                    <td class="{self._get_risk_class(strategy['average_risk'])}">{strategy['average_risk']:.2f}</td>
                    <td>{strategy['implementation_priority']}</td>
                    <td>{strategy['total_cost_range']}</td>
                </tr>
            """
            
        html += """
                </table>
            </div>
        """
        
        for asset_type, assessments in self.threat_assessment.items():
            if not assessments:
                continue
                
            html += f"""
            <div class="section">
                <div class="asset-header">
                    <h2>{asset_type.capitalize()}</h2>
                    <p>Average Risk Score: <span class="{self._get_risk_class(self.defense_strategy[asset_type]['average_risk'])}">{self.defense_strategy[asset_type]['average_risk']:.2f}/10</span></p>
                    <p>Priority: {self.defense_strategy[asset_type]['implementation_priority']}</p>
                </div>
                
                <h3>Common Vulnerability Factors</h3>
                <ul>
            """
            
            for factor_type, factor_value in self.defense_strategy[asset_type]["vulnerabilities"].items():
                html += f"""
                    <li><strong>{factor_type.replace('_', ' ').title()}:</strong> {factor_value}</li>
                """
                
            html += """
                </ul>
                
                <h3>Recommended Security Measures</h3>
            """
            
            for measure in self.defense_strategy[asset_type]["detailed_measures"]:
                html += f"""
                <div class="measure">
                    <h4>{measure['name']}</h4>
                    <p><strong>Cost:</strong> {measure['cost_range']}</p>
                    <p><strong>Implementation Time:</strong> {measure['implementation_time']}</p>
                    <p><strong>Effectiveness:</strong> {measure['effectiveness']}</p>
                    <p><strong>Description:</strong> {measure['description']}</p>
                </div>
                """
                
            html += """
            </div>
            """
            
        html += """
        </body>
        </html>
        """
        
        return html
    
    def _get_risk_class(self, risk_score: float) -> str:
        """Get CSS class based on risk score."""
        if risk_score >= 7:
            return "high-risk"
        elif risk_score >= 5:
            return "medium-risk"
        else:
            return "low-risk"
    
    def _generate_markdown_report(self) -> str:
        """Generate a markdown vulnerability report."""
        lines = []
        
        lines.append("# Power Infrastructure Vulnerability Assessment Report")
        lines.append("")
        lines.append(f"**Location:** {self.place_name or 'Custom Location'}")
        lines.append(f"**Assessment Date:** {pd.Timestamp.now().strftime('%Y-%m-%d')}")
        lines.append(f"**Total Assets Assessed:** {sum(len(assets) for assets in self.critical_assets.values())}")
        lines.append(f"**Overall Risk Level:** {self._calculate_overall_risk():.2f}/10")
        lines.append("")
        lines.append("---")
        
        lines.append("## Summary of Critical Assets")
        lines.append("")
        lines.append("| Asset Type | Count | Average Risk | Priority | Estimated Cost Range |")
        lines.append("| --- | --- | --- | --- | --- |")
        
        for asset_type, strategy in self.defense_strategy.items():
            lines.append(f"| {asset_type.capitalize()} | {len(self.critical_assets[asset_type])} | " + 
                         f"{strategy['average_risk']:.2f} | {strategy['implementation_priority']} | " +
                         f"{strategy['total_cost_range']} |")
        
        lines.append("")
        
        for asset_type, assessments in self.threat_assessment.items():
            if not assessments:
                continue
                
            lines.append(f"## {asset_type.capitalize()} Analysis")
            lines.append("")
            lines.append(f"**Average Risk Score:** {self.defense_strategy[asset_type]['average_risk']:.2f}/10")
            lines.append(f"**Priority:** {self.defense_strategy[asset_type]['implementation_priority']}")
            lines.append("")
            
            lines.append("### Vulnerability Factors")
            lines.append("")
            for factor_type, factor_value in self.defense_strategy[asset_type]["vulnerabilities"].items():
                lines.append(f"- **{factor_type.replace('_', ' ').title()}:** {factor_value}")
            lines.append("")
            
            lines.append("### Recommended Security Measures")
            lines.append("")
            for measure in self.defense_strategy[asset_type]["detailed_measures"]:
                lines.append(f"#### {measure['name']}")
                lines.append(f"- **Cost:** {measure['cost_range']}")
                lines.append(f"- **Implementation Time:** {measure['implementation_time']}")
                lines.append(f"- **Effectiveness:** {measure['effectiveness']}")
                lines.append(f"- **Description:** {measure['description']}")
                lines.append("")
                
            lines.append(f"**Total Estimated Cost Range:** {self.defense_strategy[asset_type]['total_cost_range']}")
            lines.append("")
            lines.append("---")
            
        return "\n".join(lines)
