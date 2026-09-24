// Bases y condiciones que acepta el chofer (por QR con una casilla, o firmando el formulario en papel).
// Si se cambia el texto, subir BASES_VERSION: cada código guarda la versión que se aceptó.
export const BASES_VERSION = 'v1-2026-09-24';

export function basesTexto(config) {
  const horas = config.estadiaHorasMax;
  return {
    version: BASES_VERSION,
    titulo: 'Bases y condiciones de ingreso y exención de responsabilidad',
    parrafos: [
      'Al enviar este formulario (o al firmarlo, en su versión en papel), declaro que los datos son verdaderos y, en mi nombre y en representación de la empresa indicada, en adelante "EL CLIENTE", solicito autorización para estacionar y mantener en el playón de camiones de Estación Ferreyra S.R.L. el vehículo del dominio declarado.',
      'EL CLIENTE declara conocer y aceptar expresamente que el predio es cedido únicamente como espacio de estacionamiento y que ni el propietario del inmueble ni sus administradores, representantes o personas vinculadas asumen obligaciones de guarda, custodia o vigilancia sobre los vehículos, sus cargas, accesorios o cualquier otro bien que permanezca en el lugar.',
      'En consecuencia, EL CLIENTE libera de toda responsabilidad al propietario del predio y a quienes gestionan o facilitan el uso del mismo por cualquier daño, deterioro, robo, hurto, incendio, vandalismo, pérdida total o parcial, fenómenos climáticos, actos de terceros o cualquier otro hecho que pudiera afectar a los vehículos, su carga o sus ocupantes durante su permanencia en el predio.',
      'EL CLIENTE asume íntegramente los riesgos derivados del ingreso, estacionamiento y permanencia de los vehículos en el lugar, comprometiéndose a mantener indemnes al propietario del predio y a quienes hayan facilitado su utilización frente a cualquier reclamo relacionado con dichos vehículos o sus cargas.',
      `Condiciones de uso: la estadía máxima es de ${horas} horas desde el ingreso; al excederla se cobra una estadía adicional. Al ingresar se retiene el carnet de conducir y se entrega la llave de un baño, que queda a cargo de quien la recibe. Para retirarse hay que avisar por el WhatsApp indicado en el cartel. Antes de devolver el carnet se revisa el estado del baño y, si algo no está en condiciones, se cobra el equivalente en litros según la tabla vigente.`,
      'Los datos se usan solo para controlar el ingreso, la permanencia y la salida del playón, y quedan registrados junto con la fecha y hora de esta aceptación.',
    ],
  };
}
