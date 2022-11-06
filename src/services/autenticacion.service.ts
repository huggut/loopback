import { /* inject, */ BindingScope, injectable} from '@loopback/core';
import {repository} from '@loopback/repository';
import {LLaves} from '../config/llaves';
import {Persona} from '../models';
import {PersonaRepository} from '../repositories';
const generador = require("password-generator");
const cryptoJS = require("crypto-js");
const jwt = require("jsonwebtoken");

@injectable({scope: BindingScope.TRANSIENT})
export class AutenticacionService {
  constructor(
    @repository(PersonaRepository)
    public personaRepository: PersonaRepository
  ) { }

  generarClave() {
    const clave = generador(8, false);
    return clave;
  }

  cifrarClave(clave: string) {
    const claveCifrada = cryptoJS.MD5(clave).toString();
    return claveCifrada;
  }

  //Autenticacion
  identificarPersona(usuario: string, clave: string) {
    try {
      const p = this.personaRepository.findOne(
        {
          where: {
            correo: usuario,
            clave: clave
          }
        }
      );
      if (p) {
        return p;
      }
      return false;
    } catch {
      return false;
    }
  }

  generarTokenJWT(persona: Persona) {
    const token = jwt.sign({
      data: {
        id: persona.id,
        correo: persona.correo,
        nombre: persona.nombre + " " + persona.apellidos
        //rol: persona.rol
      }
    }, LLaves.claveJWT);
    return token;
  }

  validarTokenJWT(token: string) {
    try {
      const datos = jwt.verify(token, LLaves.claveJWT);
      return datos;
    } catch {
      return false;
    }
  }
}
