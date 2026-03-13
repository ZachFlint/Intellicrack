try:
    import PyQt6
    print("PyQt6 available")
except ImportError:
    print("PyQt6 NOT available")
    
try:
    import torch
    print("torch available")
except ImportError:
    print("torch NOT available")
