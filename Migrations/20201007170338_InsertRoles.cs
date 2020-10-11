using Microsoft.EntityFrameworkCore.Migrations;

namespace IdentitySample.Migrations
{
    public partial class InsertRoles : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.InsertData(
                table: "AspNetRoles",
                columns: new[] { "Id", "ConcurrencyStamp", "Name", "NormalizedName" },
                values: new object[] { "b0fffd10-b264-4b1e-9a8a-763f668bdfed", "14c6dac9-ce16-4492-aa1c-ec24106ccf79", "Visitor", "VISITOR" });

            migrationBuilder.InsertData(
                table: "AspNetRoles",
                columns: new[] { "Id", "ConcurrencyStamp", "Name", "NormalizedName" },
                values: new object[] { "46e25884-4282-4197-afa3-2a67cd1473a8", "ab505765-2ca2-44e2-afd2-4502e0953858", "Admin", "ADMIN" });
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "46e25884-4282-4197-afa3-2a67cd1473a8");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "b0fffd10-b264-4b1e-9a8a-763f668bdfed");
        }
    }
}
