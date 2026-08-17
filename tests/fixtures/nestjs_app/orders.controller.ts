import { Body, Controller, Get, Param, Post, Query, UseGuards } from "@nestjs/common";
import { ApiProperty } from "@nestjs/swagger";
import { IsEmail, IsInt, Min, MinLength } from "class-validator";

export class CreateOrderDto {
  @ApiProperty()
  @MinLength(2)
  title: string;

  @ApiProperty()
  @IsEmail()
  contact_email: string;

  @ApiProperty()
  @IsInt()
  @Min(1)
  customer_id: number;
}

@Controller("orders")
@UseGuards(JwtAuthGuard)
export class OrdersController {
  @Get(":id")
  findOne(@Param("id") id: string, @Query("q") q: string) {
    return { id, q };
  }

  @Post()
  create(@Body() dto: CreateOrderDto) {
    return dto;
  }
}
