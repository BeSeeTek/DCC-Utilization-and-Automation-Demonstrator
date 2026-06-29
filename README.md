**Overview**

This application allows engineers and scientists to analyze temperature sensor measurements using associated DCCs (Digital Calibration Certificates). The DCC data is used to correct measurements and perform live uncertainty
calculations.

The programm simulates a a process that needs to be temperature controlled. Originally an Arduino with four PT100 sensors was used. But the programm can also simulate measurement data. 
The main idea of the visualization is to compare sensor measurements with and without DCC correction side by side, so users can instantly see the impact of the usage of the calibration data from the DCC on the measurement
results.

**Target Users**

Engineers and scientists in metrology, calibration, and quality assurance.

Users needing to analyze temperature sensor measurements with automated corrections and certificate-based DCC validation.

🌟 **Key Features**

| Feature | Description |
|---------|-------------|
| Sensor Data Visualization | Each sensor has its own tab showing raw and corrected measurements side by side. |
| DCC Validation | Schema validation against XSD, integrity check after sealing, and full certificate chain verification up to the root certificate. |
| Dynamic Plotting | Real-time updating plots for up to 4 sensors. |
| Drag-and-Drop XML Loading | Load DCC files directly into the GUI for quick and fully automated analysis. |
|Interactive GUI | Message boxes for decisions regarding the usage of the DCC and Treeview widgets for structured data display. |
| Logging & Event System | Message boxes for decisions regarding the usage of the DCC and Treeview widgets for structured data display. |

🎯 **Usage**

- Drag and drop DCC XML files into the GUI.

- The DCC is validated against the schema, checked for post-sealing modifications, and the certificate chain is verified.

- Sensor measurements are displayed in dynamic plots with a side-by-side comparison: raw vs. DCC-corrected.


⚙️ **Installation**
> **Note:** OpenSSL must be installed on your system to enable full DCC validation (certificate and integrity checks). On Windows, you can install it from [Shining Light Productions](https://slproweb.com/products/Win32OpenSSL.html). Linux and macOS usually have OpenSSL pre-installed.
1. Install Python 3.12.
3. Install required dependencies:
   ```bash
   pip install -r requirements.txt
4. Clone this repository:
   ```bash
   git clone https://github.com/Nanine-Br/DCC-Utilization-and-Automation-Demonstrator.git
5. Run the main script:
   ```bash
   python main.py

📄 **License**

This project is licensed under the MIT License

**DOI**

<img width="191" height="20" alt="image" src="https://github.com/user-attachments/assets/f0f741c3-eb4a-44f0-87bb-3a7226d0d4a1" />

