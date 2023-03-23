import { createParamDecorator, ExecutionContext, NotFoundException } from "@nestjs/common";

export const User = createParamDecorator((filter: string, context: ExecutionContext) => {

    const request = context.switchToHttp().getRequest();

    if (request.user) {

        if(filter){
            return request.user[filter];
        }else{
            return request.user;
        }

        return request.user;

    } else {
        throw new NotFoundException("Usuario não encontrado no Request. Use o AuthGuard para obter o usuario")
    }

});