# Windows Event Analyzer

## Descripción

El **Windows Event Analyzer** es un script de Python diseñado para analizar eventos de Windows y detectar actividades maliciosas mediante la identificación de IDs de eventos específicos. Es una herramienta útil para administradores de sistemas y analistas de seguridad, permitiendo la exportación de eventos sospechosos a un archivo CSV para un análisis posterior.

## Funcionalidades

- **Análisis de Eventos**: Filtra los eventos de Windows basándose en los IDs proporcionados por el usuario.
- **Exportación a CSV**: Los eventos maliciosos se guardan en un archivo CSV para un análisis más detallado.


## Requisitos

- Python 3.x
- Módulos:
  - `pywin32`: Para interactuar con los registros de eventos de Windows.

## Instalación

1. Clona este repositorio o descarga el script directamente.
2. Asegúrate de tener Python y `pywin32` instalados. Puedes instalar `pywin32` usando pip:

   ```bash
   pip install pywin32


## Uso

Ejecuta el script desde la línea de comandos proporcionando los parámetros necesarios:
    ```bash
    python3 windows_event_analyzer.py --log_type Security --event_ids 4625,4673,4688 --output_file resultado_eventos.csv
