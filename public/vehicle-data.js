/*
 * UK vehicle makes → models — for the reg lookup & tyre finder.
 * Covers the makes actually seen on UK roads. Used to power the manual
 * "find by vehicle" picker and to tidy up make/model names returned from the
 * DVLA / Vehicle Data Global reg lookup. Tyre SIZES always come from the live
 * fitment API (never guessed here).
 *
 * window.CAR_DATA = { "Make": ["Model", ...], ... }
 * window.CAR_MAKES = ["Abarth", "Alfa Romeo", ...] (sorted)
 */
(function () {
  const DATA = {
    "Abarth": ["500", "595", "695", "124 Spider"],
    "Alfa Romeo": ["MiTo", "Giulietta", "Giulia", "Stelvio", "159", "Brera", "Tonale"],
    "Aston Martin": ["Vantage", "DB9", "DB11", "DBS", "Rapide", "DBX"],
    "Audi": ["A1", "A3", "A4", "A5", "A6", "A7", "A8", "Q2", "Q3", "Q5", "Q7", "Q8", "TT", "R8", "e-tron", "S3", "S4", "RS3", "RS4", "RS6"],
    "Bentley": ["Continental", "Flying Spur", "Bentayga", "Mulsanne"],
    "BMW": ["1 Series", "2 Series", "3 Series", "4 Series", "5 Series", "6 Series", "7 Series", "8 Series", "X1", "X2", "X3", "X4", "X5", "X6", "X7", "Z4", "i3", "i4", "iX", "M2", "M3", "M4", "M5"],
    "Citroen": ["C1", "C2", "C3", "C3 Aircross", "C4", "C4 Cactus", "C5", "C5 Aircross", "Berlingo", "DS3", "DS4", "Picasso", "Nemo", "Relay"],
    "Cupra": ["Formentor", "Leon", "Born", "Ateca"],
    "Dacia": ["Sandero", "Duster", "Logan", "Jogger", "Spring"],
    "DS": ["DS3", "DS4", "DS7", "DS9"],
    "Fiat": ["500", "500L", "500X", "Panda", "Punto", "Tipo", "Doblo", "Ducato", "Qubo"],
    "Ford": ["Fiesta", "Focus", "Ka", "Puma", "Kuga", "EcoSport", "Mondeo", "S-Max", "C-Max", "Galaxy", "Edge", "Mustang", "Ranger", "Transit", "Transit Custom", "Transit Connect"],
    "Honda": ["Jazz", "Civic", "CR-V", "HR-V", "Accord", "e", "CR-Z", "Insight"],
    "Hyundai": ["i10", "i20", "i30", "i40", "Bayon", "Kona", "Tucson", "Santa Fe", "Ioniq", "Ioniq 5", "ix20", "ix35"],
    "Jaguar": ["XE", "XF", "XJ", "F-Type", "E-Pace", "F-Pace", "I-Pace"],
    "Jeep": ["Renegade", "Compass", "Cherokee", "Grand Cherokee", "Wrangler", "Avenger"],
    "Kia": ["Picanto", "Rio", "Ceed", "ProCeed", "Stonic", "Xceed", "Sportage", "Sorento", "Niro", "Soul", "Venga", "EV6", "Optima"],
    "Land Rover": ["Defender", "Discovery", "Discovery Sport", "Range Rover", "Range Rover Sport", "Range Rover Evoque", "Range Rover Velar", "Freelander"],
    "Lexus": ["CT", "IS", "ES", "GS", "LS", "UX", "NX", "RX", "RC", "RZ"],
    "Maserati": ["Ghibli", "Quattroporte", "Levante", "GranTurismo", "Grecale"],
    "Mazda": ["Mazda2", "Mazda3", "Mazda6", "CX-3", "CX-30", "CX-5", "CX-60", "MX-5", "MX-30"],
    "Mercedes-Benz": ["A-Class", "B-Class", "C-Class", "CLA", "CLS", "E-Class", "S-Class", "GLA", "GLB", "GLC", "GLE", "GLS", "SL", "SLK", "SLC", "V-Class", "Vito", "Sprinter", "EQA", "EQB", "EQC"],
    "MG": ["MG3", "ZS", "HS", "MG4", "MG5", "ZT", "TF"],
    "MINI": ["Hatch", "Cooper", "Clubman", "Countryman", "Convertible", "Paceman", "Electric"],
    "Mitsubishi": ["Mirage", "ASX", "Eclipse Cross", "Outlander", "Shogun", "L200"],
    "Nissan": ["Micra", "Note", "Leaf", "Juke", "Qashqai", "X-Trail", "Ariya", "Pulsar", "370Z", "GT-R", "Navara", "NV200"],
    "Peugeot": ["108", "208", "308", "408", "508", "2008", "3008", "5008", "Partner", "Rifter", "Expert", "Boxer", "RCZ"],
    "Polestar": ["2", "3", "4"],
    "Porsche": ["911", "718 Cayman", "718 Boxster", "Panamera", "Macan", "Cayenne", "Taycan"],
    "Renault": ["Clio", "Captur", "Megane", "Zoe", "Kadjar", "Arkana", "Scenic", "Grand Scenic", "Kangoo", "Trafic", "Master", "Twingo"],
    "Seat": ["Ibiza", "Leon", "Arona", "Ateca", "Tarraco", "Alhambra", "Mii"],
    "Skoda": ["Citigo", "Fabia", "Scala", "Octavia", "Superb", "Kamiq", "Karoq", "Kodiaq", "Enyaq", "Rapid", "Yeti"],
    "Smart": ["ForTwo", "ForFour", "Roadster"],
    "SsangYong": ["Tivoli", "Korando", "Rexton", "Musso"],
    "Subaru": ["Impreza", "XV", "Forester", "Outback", "Legacy", "BRZ", "WRX"],
    "Suzuki": ["Alto", "Celerio", "Swift", "Baleno", "Ignis", "Vitara", "S-Cross", "Jimny", "SX4"],
    "Tesla": ["Model 3", "Model S", "Model X", "Model Y"],
    "Toyota": ["Aygo", "Yaris", "Yaris Cross", "Corolla", "C-HR", "Prius", "Camry", "RAV4", "Highlander", "Land Cruiser", "Hilux", "GT86", "Supra", "Proace", "Auris", "Avensis"],
    "Vauxhall": ["Corsa", "Astra", "Insignia", "Adam", "Viva", "Crossland", "Grandland", "Mokka", "Combo", "Vivaro", "Movano", "Zafira", "Meriva", "Antara"],
    "Volkswagen": ["up!", "Polo", "Golf", "Golf GTI", "Golf R", "Passat", "Arteon", "T-Cross", "T-Roc", "Tiguan", "Touareg", "Touran", "Sharan", "Caddy", "Transporter", "Crafter", "ID.3", "ID.4", "ID.5", "Beetle", "Scirocco"],
    "Volvo": ["V40", "V60", "V90", "S60", "S90", "XC40", "XC60", "XC90", "C40", "C30"]
  };
  const MAKES = Object.keys(DATA).sort((a, b) => a.localeCompare(b));
  window.CAR_DATA = DATA;
  window.CAR_MAKES = MAKES;
  // normalise a make/model string coming back from the reg API to our canonical casing
  window.canonMake = function (raw) {
    if (!raw) return "";
    const s = String(raw).trim().toLowerCase();
    for (const m of MAKES) if (m.toLowerCase() === s) return m;
    for (const m of MAKES) if (s.indexOf(m.toLowerCase()) === 0 || m.toLowerCase().indexOf(s) === 0) return m;
    return String(raw).trim();
  };
})();
