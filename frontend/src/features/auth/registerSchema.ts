import * as yup from "yup";

export const registerSchema = yup.object({
  email: yup.string().required("Email is required").email("Invalid email"),

  password: yup
    .string()
    .required("Password is required")
    .min(6, "Minimum 6 characters"),

  confirmPassword: yup
    .string()
    .required("Password is required")
    .oneOf([yup.ref("password")], "Passwords must match"),
});
