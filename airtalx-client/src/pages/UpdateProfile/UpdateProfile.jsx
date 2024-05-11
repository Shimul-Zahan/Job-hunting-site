import { AuthContext } from "../../providers/AuthProviders";
import { message, Form, Input, Upload, Button, Select } from "antd";
import { UploadOutlined } from "@ant-design/icons";
import axios from "axios";
import { Option } from "antd/es/mentions";
import { useContext, useRef, useState } from "react";
import JoditEditor from 'jodit-react';

const UpdateProfile = () => {
  const { user, setUser } = useContext(AuthContext);
  const [fileList, setFileList] = useState([]);
  const [content1, setContent1] = useState('');
  const [content2, setContent2] = useState('');
  const editor1 = useRef(null);
  const editor2 = useRef(null);
  const [form] = Form.useForm();

  const onGenderChange = (value) => {
    switch (value) {
      case "male":
        form.setFieldsValue({
          // note: 'Hi, man!',
        });
        break;
      case "female":
        form.setFieldsValue({
          // note: 'Hi, lady!',
        });
        break;
      case "other":
        form.setFieldsValue({
          // note: 'Hi there!',
        });
        break;
      default:
    }
  };
  const onGenderChange2 = (value) => {
    switch (value) {
      case "male":
        form.setFieldsValue({
          // note: 'Hi, man!',
        });
        break;
      case "female":
        form.setFieldsValue({
          // note: 'Hi, lady!',
        });
        break;
      case "other":
        form.setFieldsValue({
          // note: 'Hi there!',
        });
        break;
      default:
    }
  };

  const normFile = (e) => {
    setFileList(e.fileList);
    // console.log(e.fileList);
    if (Array.isArray(e)) {
      return e;
    }
    return e?.fileList;
  };

  const props = {
    multiple: false,
    onRemove: (file) => {
      const index = fileList.indexOf(file);
      const newFileList = fileList.slice();
      newFileList.splice(index, 1);
      setFileList(newFileList);
    },
    beforeUpload: () => {
      return false;
    },
    fileList,
  };

  const onFinish = async (values) => {
    console.log("🚀 ~ onFinish ~ values:", values);
    try {
      const {
        name,
        location,
        country,
        studies,
        about,
        newPassword,
        preferredSalary,
        preferredJobType,
        expertiseField,
        expertiseLevel,
        jobPosition,
        jobCompanyName,
        jobCompanySize,
        aboutCompany,
        industry,
      } = values || {};

      const data = new FormData();
      data.append("name", name || user?.name);
      data.append("password", newPassword);
      data.append("location", location || user?.location);
      data.append("country", country || user?.country);
      data.append("studies", studies || user?.studies);
      data.append("about", content1);
      data.append("preferredSalary", preferredSalary || user?.preferredSalary);
      data.append("expertiseField", expertiseField || user?.expertiseField);
      data.append(
        "preferredJobType",
        preferredJobType || user?.preferredJobType
      );
      data.append("expertiseLevel", expertiseLevel || user?.expertiseLevel);
      data.append("jobPosition", jobPosition || user?.jobPosition);
      data.append("jobCompanyName", jobCompanyName || user?.jobCompanyName);
      data.append("jobCompanySize", jobCompanySize || user?.jobCompanySize);
      data.append("industry", industry || user?.industry);
      data.append("aboutCompany", content2);
      data.append("role", user?.role);
      data.append("oldPass", user?.password);
      data.append("isUpdate", newPassword ? "False" : "True");
      data.append("images", fileList[0]?.originFileObj || "");
      const config = {
        headers: {
          "content-type": "multipart/form-data",
        },
      };
      const url = `http://localhost:5000/update/${user?.email}`;
      try {
        const response = await axios.put(url, data, config);
        console.log("🚀 ~ onFinish ~ response:", response);
        if (response.data.user) {
          message.success("Profile Updated!");
          setUser(response.data.user);
          localStorage.setItem("access-token", response.data.token);
          form.resetFields();
        } else {
          message.error(response.data.message || "Failed to update profile");
        }
      } catch (error) {
        console.error("Update failed:", error);
        message.error("Failed to update. Please try again later.");
      }
    } catch (error) {
      console.error("Profile update failed:", error);
      message.error("Failed to update profile. Please try again later.");
    }
  };

  const onFinishFailed = (errorInfo) => {
    console.log("Failed:", errorInfo);
  };

  return (
    <div className="lg:w-1/2 w-11/12 mx-auto">
      <div className="mx-auto w-11/12 mb-4">
        <h2 className="text-3xl pb-3 text-center font-semibold my-5">
          Update Your Profile
        </h2>
        <Form
          name="update_profile"
          initialValues={user}
          onFinish={onFinish}
          onFinishFailed={onFinishFailed}
          form={form}
        >
          <Form.Item label="User Name" name="name" initialValue={user?.name}>
            <Input />
          </Form.Item>

          {user && user?.role === "jobseeker" && (
            <>
              <Form.Item
                label="Location"
                name="location"
                initialValue={user?.location}
              >
                <Input />
              </Form.Item>
              <Form.Item
                label="Education"
                name="studies"
                initialValue={user?.studies}
              >
                <Input />
              </Form.Item>
              <Form.Item
                label="Preferred Salary"
                name="preferredSalary"
                initialValue={user?.preferredSalary}
              >
                <Input placeholder={'please enter a value between $3 and $99'} />
              </Form.Item>
              <Form.Item name="preferredJobType" label="Preferred Job Type">
                <Select
                  placeholder="Select an option"
                  onChange={onGenderChange2}
                  allowClear
                  className="z-10"
                  initialValue={user?.preferredJobType}
                >
                  <Option value="Beginner: 1-2 years of experience">Full Time</Option>
                  <Option value="Intermediate: 3-5 years of experience">Part Time</Option>
                </Select>
              </Form.Item>
              <Form.Item
                label="Expertise Field"
                name="expertiseField"
                initialValue={user?.expertiseField}
              >
                <Input />
              </Form.Item>
              <Form.Item name="expertiseLevel" label="Expertise Level">
                <Select
                  placeholder="Select an option"
                  onChange={onGenderChange}
                  allowClear
                  className="z-10"
                >
                  <Option value="Beginner: 1-2 years of experience">Beginner: 1-2 years of experience</Option>
                  <Option value="Intermediate: 3-5 years of experience">Intermediate: 3-5 years of experience</Option>
                  <Option value="Advanced: 6+ years of experience">Advanced: 6+ years of experience</Option>
                </Select>
              </Form.Item>
            </>
          )}
          <Form.Item
            name="user_image"
            valuePropName="fileList"
            label="Image"
            getValueFromEvent={normFile}
          >
            <Upload
              name="logo"
              action="/upload.do"
              listType="picture"
              {...props}
            >
              <Button icon={<UploadOutlined />}>Click to upload Image</Button>
            </Upload>
          </Form.Item>
          <Form.Item
            label="Location"
            name="location"
            initialValue={user?.location}
          >
            <Input />
          </Form.Item>
          <Form.Item
            label="Country"
            name="country"
            initialValue={user?.country}
          >
            <Input />
          </Form.Item>
          <Form.Item label="Bio" name="about" initialValue={user?.about}>
            {/* <Input.TextArea /> */}
            <div className="custom-class no-tailwind custom-ul custom-ol">
              <JoditEditor ref={editor1} value={content1} initialValue={user?.about} onChange={newContent => setContent1(newContent)} />
            </div>
          </Form.Item>
          <Form.Item
            label="Current Company Name"
            name="jobCompanyName"
            initialValue={user?.jobCompanyName}
          >
            <Input />
          </Form.Item>
          <Form.Item
            label="Job Position"
            name="jobPosition"
            initialValue={user?.jobPosition}
          >
            <Input />
          </Form.Item>
          <Form.Item
            label="Industry"
            name="industry"
            initialValue={user?.industry}
          >
            <Input />
          </Form.Item>
          <Form.Item name="jobCompanySize" label="Company Size">
            <Select
              placeholder="Select an option"
              allowClear
              className="z-10"
              initialValue={user?.jobCompanySize}
            >
              <Option value="">Select</Option>
              <Option value="1-10">1-10</Option>
              <Option value="11-20">11-20</Option>
              <Option value="21-50">21-50</Option>
              <Option value="51-100">51-100</Option>
              <Option value="101-200">101-200</Option>
              <Option value="201-500">201-500</Option>
              <Option value="501-1000">501-1000</Option>
              <Option value="1001-2000">1001-2000</Option>
              <Option value="2001-5000">2001-5000</Option>
              <Option value="5001-10000">5001-10000</Option>
              <Option value="10001 plus">10001 plus</Option>
            </Select>
          </Form.Item>
          <Form.Item label="About Company" name="aboutCompany" initialValue={user?.about}>
            {/* <Input.TextArea /> */}
            <div className="custom-class no-tailwind custom-ul custom-ol">
              <JoditEditor ref={editor2} value={content2} initialValue={user?.aboutCompany} onChange={newContent => setContent2(newContent)} />
            </div>
          </Form.Item>
          <Form.Item label="Password" name="newPassword">
            <Input.Password placeholder="Enter New Password" />
          </Form.Item>
          <Form.Item>
            <Button type="primary" htmlType="submit" className="w-full">
              Update
            </Button>
          </Form.Item>
        </Form>
      </div>
    </div>
  );
};

export default UpdateProfile;
