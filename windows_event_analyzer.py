import csv
import win32evtlog
import argparse
import ctypes
import sys


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def analizar_eventos(log_type, id_eventos_maliciosos):
    server = 'localhost'  # Analizar eventos locales
    log = win32evtlog.OpenEventLog(server, log_type)

    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    eventos_maliciosos = []

    # Leer los eventos
    while True:
        eventos = win32evtlog.ReadEventLog(log, flags, 0)
        if eventos:
            for evento in eventos:
                if evento.EventID in id_eventos_maliciosos:
                    datos_evento = {
                        'ID': evento.EventID,
                        'Tipo': evento.EventType,
                        'Origen': evento.SourceName,
                        'Hora': evento.TimeGenerated.Format(),
                        'Descripcion': evento.StringInserts,
                    }
                    eventos_maliciosos.append(datos_evento)
        else:
            break

    win32evtlog.CloseEventLog(log)
    return eventos_maliciosos


def guardar_en_csv(eventos, archivo_salida):
    with open(archivo_salida, mode='w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=['ID', 'Tipo', 'Origen', 'Hora', 'Descripcion'])
        writer.writeheader()
        for evento in eventos:
            writer.writerow(evento)


def main():

    if not is_admin():
        print("Requiere privilegios administrativos, solicitando permisos...")
        sys.exit(1)

    parser = argparse.ArgumentParser(description='Analizar eventos de Windows y exportar eventos maliciosos a CSV.')    
    parser.add_argument('--log_type', type=str, default='Security', help='Tipo de log de eventos de Windows (por ejemplo, Security, Application, System).')
    parser.add_argument('--event_ids', type=str,  help='IDs de eventos maliciosos separados por comas (por ejemplo, 4625,4673,4688).')
    parser.add_argument('--output_file', type=str, default='eventos_maliciosos.csv', help='Archivo de salida CSV.')

    args = parser.parse_args()

    if args.event_ids:
        id_eventos_maliciosos = list(map(int, args.event_ids.split(',')))
    else:
        print("No se han proporcionado IDs de eventos maliciosos.")
        return
    
    eventos_maliciosos = analizar_eventos(args.log_type, id_eventos_maliciosos)

    guardar_en_csv(eventos_maliciosos, args.output_file)

    print(f"Análisis completado. Los eventos maliciosos se han guardado en {args.output_file}.")

if __name__ == '__main__':
    main()
