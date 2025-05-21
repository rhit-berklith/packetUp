import tkinter as tk
from tkinter import ttk
from tkintermapview import TkinterMapView

class MapFrame(ttk.LabelFrame):
    def __init__(self, parent, *args, **kwargs):
        super().__init__(parent, text="Earth Map", *args, **kwargs)
        self.map_widget = None
        self.setup_map_widget()
        self.markers = []  # Keep track of markers to clean up on exit
        self.active_temp_markers = {}

    def setup_map_widget(self):
        # Clear any existing widgets in this frame, though typically it's new
        for widget in self.winfo_children():
            widget.destroy()
        
        print("[MAP] Initializing TkinterMapView widget") # DIAGNOSTIC
        self.map_widget = TkinterMapView(self, width=600, height=300, corner_radius=0)
        self.map_widget.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Set a default position and zoom
        self.map_widget.set_position(20, 0)  # Example: Latitude 20, Longitude 0
        self.map_widget.set_zoom(2)
        
        print("[MAP] TkinterMapView widget initialized and positioned.") # DIAGNOSTIC

    def add_temporary_marker(self, lat, lon, text="", duration_ms=2000):
        """Add a small red dot at the specified coordinates that disappears after duration_ms milliseconds."""
        if not self.map_widget:
            return None
            
        # only one temp‐marker per location
        if (lat, lon) in self.active_temp_markers:
            return
        
        try:
            # Create a simple marker with minimal parameters
            marker = self.map_widget.set_marker(
                lat, lon, 
                text="",  # No text
                marker_color_circle="red",
                marker_color_outside="red"  # Same color for a simple dot appearance
            )
            
            if marker:
                # Store marker in our list
                self.markers.append(marker)
                self.active_temp_markers[(lat, lon)] = marker
                # schedule a single removal
                self.map_widget.after(duration_ms, lambda lat=lat, lon=lon: self._remove_temp_marker(lat, lon))
            return marker
        except Exception as e:
            print(f"[MAP] Error creating marker at ({lat}, {lon}): {e}")
            return None

    def _remove_temp_marker(self, latitude, longitude):
        marker = self.active_temp_markers.pop((latitude, longitude), None)
        if marker:
            try:
                marker.delete()
            except Exception as e:
                print(f"[MAP] Error deleting marker: {e}")
                # Still remove from our tracking list even if deletion failed
                if marker in self.markers:
                    self.markers.remove(marker)
    
    def clear_all_markers(self):
        """Clear all markers from the map - useful when stopping capture."""
        markers_to_delete = self.markers.copy()
        for marker in markers_to_delete:
            try:
                marker.delete()
            except:
                pass  # Ignore errors during cleanup
        self.markers.clear()
        self.active_temp_markers.clear()

if __name__ == '__main__':
    root = tk.Tk()
    root.title("Map Test")
    root.geometry("700x400")
    
    map_component = MapFrame(root)
    map_component.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
    
    # Example of how to access the map_widget from outside (if needed)
    # map_component.map_widget.set_address("Berlin Germany")

    # Test temporary marker
    map_component.add_temporary_marker(52.5200, 13.4050, text="Berlin Temp", duration_ms=5000) # Berlin
    map_component.add_temporary_marker(40.7128, -74.0060, text="NYC Temp", duration_ms=3000)    # New York
    
    root.mainloop()
