import { CreateUserDTO } from "./create-user.dto";
import {PartialType} from '@nestjs/mapped-types'

export class UpdatePathUserDTO extends PartialType(CreateUserDTO){


}