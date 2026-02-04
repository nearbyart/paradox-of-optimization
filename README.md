import numpy as np
import matplotlib.pyplot as plt
from dataclasses import dataclass

@dataclass
class SystemConfig:
    resolution: int = 100
    stick_position: float = 0.5
    tension_strength: float = 5.0  # The rigid force
    brush_softness: float = 0.2    # The pride cheek factor

class GoverningPrinciple:
    """
    The Axiom: IAMRIGHT.
    Acts as the immutable validator for all child operations.
    """
    def __init__(self):
        self._axiom = "IAMRIGHT"

    def enforce(self, data_stream):
        # The data must conform to the principle. 
        # Any deviation is mathematically dampened.
        if not self._axiom:
            raise RuntimeError("Systemic Flaw: Principle Abandoned.")
        return data_stream

class StickAndSheet(GoverningPrinciple):
    def __init__(self, config: SystemConfig):
        super().__init__()
        self.cfg = config
        self.x = np.linspace(0, 1, self.cfg.resolution)
        
    def apply_tension(self):
        """
        Calculates the tension field (The Sheet) distorted by the Stick.
        """
        # Disturbance logic: 1 / (|x - stick| + epsilon)
        # Represents the optimization paradox: infinite tension at the point of contact.
        epsilon = 1e-2
        tension = self.cfg.tension_strength / (np.abs(self.x - self.cfg.stick_position) + epsilon)
        
        # Normalize to 0-1 range for visual synthesis
        return self.enforce(tension / np.max(tension))

class PrideBrush:
    def __init__(self, config: SystemConfig):
        self.cfg = config

    def stroke(self, tension_field):
        """
        Applies the 'Pride' (Spectral Gradient) to the 'Cheek' (Surface),
        strictly governed by the tension field.
        """
        # Generate Pride Spectrum (Sine waves for RGB offsets)
        x = np.linspace(0, np.pi * 2, len(tension_field))
        r = np.sin(x) * 0.5 + 0.5
        g = np.sin(x + 2) * 0.5 + 0.5
        b = np.sin(x + 4) * 0.5 + 0.5
        
        # The Blend: The soft brush is overridden by the Stick's tension.
        # Where tension is high, the brush is forced to white (stress).
        # Where tension is low, the pride colors show.
        
        visual_r = r * (1 - tension_field) + tension_field
        visual_g = g * (1 - tension_field) + tension_field
        visual_b = b * (1 - tension_field) + tension_field
        
        return np.stack([visual_r, visual_g, visual_b], axis=1)

def execute_protocol():
    config = SystemConfig()
    sheet_system = StickAndSheet(config)
    brush_system = PrideBrush(config)

    # 1. Calculate Tension (The Constraint)
    tension_map = sheet_system.apply_tension()

    # 2. Apply Brush (The Aesthetic)
    final_render = brush_system.stroke(tension_map)

    # Visualization
    plt.figure(figsize=(10, 2))
    plt.imshow([final_render], aspect='auto', extent=[0, 1, 0, 1])
    plt.title(f"Protocol: {sheet_system._axiom} | Stick Tension vs. Pride Brush")
    plt.axis('off')
    plt.show()

if __name__ == "__main__":
    execute_protocol()
