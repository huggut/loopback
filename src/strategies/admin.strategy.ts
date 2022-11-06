import {AuthenticationStrategy} from '@loopback/authentication';
import {service} from '@loopback/core';
import {HttpErrors, Request} from '@loopback/rest';
import {UserProfile} from '@loopback/security';
import parseBearerToken from 'parse-bearer-token';
import {AutenticacionService} from '../services';

export class EstrategiaAdministrador implements AuthenticationStrategy {
  name = 'admin';

  constructor(
    @service(AutenticacionService)
    public servicioAutenticacion: AutenticacionService
  ) {

  }
  async authenticate(request: Request): Promise<UserProfile | undefined> {
    const token = parseBearerToken(request);
    if (token) {
      const datos = this.servicioAutenticacion.validarTokenJWT(token);
      if (datos) {
        //if(datos.data.rol == 'admin'){
        const perfil: UserProfile = Object.assign({
          mombre: datos.data.nombre
        });
        return perfil;
        //}
      } else {
        throw new HttpErrors[401]("Usuario inválido");
      }
    } else {
      throw new HttpErrors[401]("Usuario inválido");
    }
  }
}
